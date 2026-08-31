/**
 * Finding Triage Workflow
 * Replicates codex-security triage-finding skill + triage-result-contract.md
 * External finding intake with verdict classification and exploitability ranking
 */

import { prisma } from "@/lib/db";
import { generateText } from "@/lib/ai";
import {
  ANALYSIS_VOICE,
  JSON_OUTPUT_CONTRACT,
  SOURCE_CONTROL_SINK_FRAMEWORK,
  truncateForPrompt,
} from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export type TriageSourceType = "sarif" | "cve" | "advisory" | "scanner_ticket" | "bug_bounty" | "freeform";
export type TriageVerdict = "confirmed" | "not_actionable" | "needs_review";

export interface TriageInput {
  inputId?: string;
  sourceType: TriageSourceType;
  title: string;
  description?: string;
  component?: string;
  cweId?: string;
  cveId?: string;
  affectedPath?: string;
  claimedSource?: string;
  claimedSink?: string;
  claimedImpact?: string;
  preconditions?: string;
  references?: string[];
}

export interface TriageVerdictResult {
  verdict: TriageVerdict;
  confidence: "high" | "medium" | "low";
  rationale: string;
  boundaryAssessment: {
    surface: string;
    sourceTrust: string;
    policyBasis: string;
    boundaryCrossed: boolean;
  };
  evidence: string;
  counterevidence: string;
  proofGaps: string;
  affectedPaths: Array<{ path: string; line?: number; role: string }>;
  recommendedNext: string;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

export function buildTriagePrompt(finding: TriageInput, repoContext?: string): string {
  return `${ANALYSIS_VOICE}

## Task
Triage this existing security finding against the repository using static code evidence.
Return one evidence-backed verdict: confirmed, not_actionable, or needs_review.

## Input Finding
- Source type: ${finding.sourceType}
- Title: ${finding.title}
- Component: ${finding.component || "Unknown"}
- CWE: ${finding.cweId || "Unknown"}
- CVE: ${finding.cveId || "None"}
- Description: ${finding.description || "Not provided"}
- Claimed source: ${finding.claimedSource || "Not specified"}
- Claimed sink: ${finding.claimedSink || "Not specified"}
- Claimed impact: ${finding.claimedImpact || "Not specified"}
- Preconditions: ${finding.preconditions || "None stated"}
- Affected path: ${finding.affectedPath || "Not specified"}
${finding.references?.length ? `- References: ${finding.references.join(", ")}` : ""}

${repoContext ? `## Repository Context\n${truncateForPrompt(repoContext, 2000)}\n` : ""}
${SOURCE_CONTROL_SINK_FRAMEWORK}

## Verdict Rules
- **confirmed**: Static evidence positively establishes the vulnerable condition exists, a shipped path reaches it, the claimed actor can influence the source, and the consequence crosses a security boundary.
- **not_actionable**: Static evidence positively defeats the material claim across plausible shipped paths.
- **needs_review**: Source provenance, control semantics, or boundary policy cannot be established statically.

## Surface & Boundary Gate
Before confirming, classify:
- Product surface (CLI, library API, hosted service, test/demo, generated code)
- Source trust level (untrusted external input vs. trusted operator config)
- Whether a supported security boundary is actually crossed

Do NOT confirm solely because attacker data reaches a dangerous sink — establish the boundary crossing.

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "verdict": "confirmed|not_actionable|needs_review",
  "confidence": "high|medium|low",
  "rationale": "One paragraph explaining the verdict with evidence",
  "boundaryAssessment": {
    "surface": "hosted service API endpoint",
    "sourceTrust": "untrusted external input (HTTP request body)",
    "policyBasis": "No SECURITY.md found; default trust boundary applies",
    "boundaryCrossed": true
  },
  "evidence": "Concrete code evidence supporting the verdict",
  "counterevidence": "Evidence against, or 'none identified'",
  "proofGaps": "Unresolved questions, or 'none'",
  "affectedPaths": [{"path": "src/api/handler.ts", "line": 42, "role": "sink"}],
  "recommendedNext": "Suggested action (fix, investigate, dismiss)"
}`;
}

// ─── Core Triage Function ────────────────────────────────────────────────────

/**
 * Triage multiple findings against a repository
 */
export async function triageFindings(
  inputs: TriageInput[],
  companyId: string,
  repoContext?: string
): Promise<Array<TriageVerdictResult & { input: TriageInput }>> {
  const results: Array<TriageVerdictResult & { input: TriageInput }> = [];

  for (const input of inputs.slice(0, 50)) {
    const prompt = buildTriagePrompt(input, repoContext);

    try {
      const response = await generateText(prompt, {
        temperature: 0.1,
        maxOutputTokens: 2000,
        companyId,
      });

      const parsed = parseTriageResponse(response?.text || "");
      if (parsed) {
        results.push({ ...parsed, input });

        // Persist to DB
        await prisma.triageResult.create({
          data: {
            companyId,
            inputId: input.inputId || null,
            sourceType: input.sourceType,
            title: input.title,
            verdict: parsed.verdict,
            confidence: parsed.confidence,
            boundaryAssessment: parsed.boundaryAssessment,
            evidence: parsed.evidence || null,
            counterevidence: parsed.counterevidence || null,
            proofGaps: parsed.proofGaps || null,
            affectedPaths: parsed.affectedPaths.length > 0 ? parsed.affectedPaths : undefined,
            recommendedNext: parsed.recommendedNext || null,
          },
        });
      }
    } catch (err) {
      console.error(`Triage failed for "${input.title}":`, err);
    }
  }

  // Assign exploitability stack ranks
  assignExploitabilityRanks(results);

  return results;
}

// ─── Exploitability Stack Ranking ────────────────────────────────────────────

/**
 * Assign discrete exploitability stack ranks within each verdict queue
 * From codex-security triage-result-contract.md
 */
function assignExploitabilityRanks(results: Array<TriageVerdictResult & { input: TriageInput }>): void {
  const confirmed = results.filter((r) => r.verdict === "confirmed");
  const needsReview = results.filter((r) => r.verdict === "needs_review");

  // Sort by confidence (high first), then by evidence length as proxy for clarity
  const sortByExploitability = (a: TriageVerdictResult, b: TriageVerdictResult) => {
    const confOrder = { high: 0, medium: 1, low: 2 };
    const confDiff = confOrder[a.confidence] - confOrder[b.confidence];
    if (confDiff !== 0) return confDiff;
    return (b.evidence?.length || 0) - (a.evidence?.length || 0);
  };

  confirmed.sort(sortByExploitability);
  needsReview.sort(sortByExploitability);

  // Assign ranks (1-based)
  confirmed.forEach((r, i) => {
    (r as unknown as Record<string, unknown>).exploitRank = i + 1;
  });
  needsReview.forEach((r, i) => {
    (r as unknown as Record<string, unknown>).exploitRank = i + 1;
  });
}

// ─── Response Parser ─────────────────────────────────────────────────────────

export function parseTriageResponse(text: string): TriageVerdictResult | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

    const verdict = (["confirmed", "not_actionable", "needs_review"].includes(String(parsed.verdict))
      ? String(parsed.verdict)
      : "needs_review") as TriageVerdict;

    const confidence = (["high", "medium", "low"].includes(String(parsed.confidence))
      ? String(parsed.confidence)
      : "medium") as "high" | "medium" | "low";

    const ba = (parsed.boundaryAssessment || {}) as Record<string, unknown>;

    return {
      verdict,
      confidence,
      rationale: String(parsed.rationale || ""),
      boundaryAssessment: {
        surface: String(ba.surface || "unknown"),
        sourceTrust: String(ba.sourceTrust || "unknown"),
        policyBasis: String(ba.policyBasis || "none"),
        boundaryCrossed: Boolean(ba.boundaryCrossed),
      },
      evidence: String(parsed.evidence || ""),
      counterevidence: String(parsed.counterevidence || ""),
      proofGaps: String(parsed.proofGaps || ""),
      affectedPaths: Array.isArray(parsed.affectedPaths)
        ? (parsed.affectedPaths as Array<{ path: string; line?: number; role: string }>)
        : [],
      recommendedNext: String(parsed.recommendedNext || ""),
    };
  } catch {
    return null;
  }
}

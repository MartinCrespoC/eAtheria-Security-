/**
 * Attack-Path Analysis
 * Replicates codex-security attack-path-analysis skill + attack-path-facts.md + severity-policy.md
 * Determines dataflow, reachability, and calibrated severity per finding
 */

import {
  ANALYSIS_VOICE,
  JSON_OUTPUT_CONTRACT,
  SHARED_HARD_RULES,
  SOURCE_CONTROL_SINK_FRAMEWORK,
  CONFIDENCE_SCALE,
  formatFindingContext,
  truncateForPrompt,
} from "./prompts";
import {
  calibrateSeverity,
  toAetheriaSeverity,
  type ImpactLevel,
  type LikelihoodLevel,
  type CalibratedSeverity,
} from "./severity-calibration";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackPathResult {
  dataflow: string; // source→control→sink path description
  reachability: string; // who can trigger, preconditions, boundary
  impact: ImpactLevel;
  likelihood: LikelihoodLevel;
  severity: CalibratedSeverity;
  rationale: string;
  changeConditions: string; // what would raise/lower severity
  counterevidence: string;
  proofGaps: string;
  rootCauseSummary: string;
  codeEvidence: CodeEvidenceItem[];
}

export interface CodeEvidenceItem {
  id: string;
  label: string;
  path: string;
  startLine: number;
  endLine?: number;
  language: string;
  role: "entrypoint" | "source" | "root_control" | "sink" | "evidence" | "expected_control";
  code: string;
  explanation: string;
}

export interface VulnContext {
  title: string;
  description: string;
  cweId?: string | null;
  filePath?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
  codeSnippet?: string | null;
  severity?: string;
  category?: string;
  detectionMethod?: string | null;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build attack-path analysis prompt for a single finding
 */
export function buildAttackPathPrompt(
  finding: VulnContext,
  threatModelContext?: string,
  additionalCode?: string
): string {
  return `${ANALYSIS_VOICE}

## Task
Perform attack-path analysis on this security finding. Determine the concrete dataflow, assess realistic reachability, and calibrate severity using impact × likelihood.

## Finding
${formatFindingContext(finding)}

${additionalCode ? `## Additional Code Context\n\`\`\`\n${truncateForPrompt(additionalCode, 2000)}\n\`\`\`\n` : ""}
${threatModelContext ? `${threatModelContext}\n` : ""}
${SOURCE_CONTROL_SINK_FRAMEWORK}

${CONFIDENCE_SCALE}

## Severity Calibration Rules
- Impact: high (RCE, data breach, auth bypass) | medium (XSS, IDOR, CSRF) | low (redirect, info leak) | ignore (theoretical)
- Likelihood: high (no auth, simple request) | medium (authenticated, multi-step) | low (admin, complex) | ignore (impossible)
- SUPPRESS to ignore if: self-only impact, unachievable precondition, requires same privilege as target, non-shipped code only

## Attack-Path Facts Required
For each finding, establish:
1. DATAFLOW: The exact source→transformations→sink path through the code
2. REACHABILITY: Who can trigger this? From what boundary? Under what preconditions?
3. IMPACT: What concrete security consequence follows? (data exposed, integrity broken, code executed)
4. LIKELIHOOD: How realistic is exploitation? (auth required? config needed? complexity?)
5. COUNTEREVIDENCE: What argues against this finding? (sanitizers, guards, type safety)
6. ROOT CAUSE: What security invariant is violated and how?

${SHARED_HARD_RULES}

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "dataflow": "request.param → controller.handler → service.process → db.query (unsanitized)",
  "reachability": "Any authenticated user via POST /api/endpoint. No special role required.",
  "impact": "high|medium|low|ignore",
  "likelihood": "high|medium|low|ignore",
  "rationale": "One-sentence severity justification grounded in evidence",
  "changeConditions": "What specific evidence would raise or lower this severity",
  "counterevidence": "Arguments against the finding, or 'none identified'",
  "proofGaps": "What remains unproven, or 'none'",
  "rootCauseSummary": "The violated security invariant and how the implementation breaks it",
  "codeEvidence": [
    {"id": "ev1", "label": "User input source", "path": "src/routes/api.ts", "startLine": 42, "endLine": 44, "language": "typescript", "role": "source", "code": "const input = req.body.query", "explanation": "Attacker-controlled input enters here"}
  ]
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

/**
 * Parse AI attack-path analysis response
 */
export function parseAttackPathResponse(text: string): AttackPathResult | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as {
      dataflow?: string;
      reachability?: string;
      impact?: string;
      likelihood?: string;
      rationale?: string;
      changeConditions?: string;
      counterevidence?: string;
      proofGaps?: string;
      rootCauseSummary?: string;
      codeEvidence?: Array<Record<string, unknown>>;
    };

    const impact = (["high", "medium", "low", "ignore"].includes(parsed.impact || "")
      ? parsed.impact
      : "medium") as ImpactLevel;
    const likelihood = (["high", "medium", "low", "ignore"].includes(parsed.likelihood || "")
      ? parsed.likelihood
      : "medium") as LikelihoodLevel;

    const severity = calibrateSeverity({ impact, likelihood });

    // Parse code evidence items
    const codeEvidence: CodeEvidenceItem[] = [];
    if (Array.isArray(parsed.codeEvidence)) {
      for (const ev of parsed.codeEvidence.slice(0, 10)) {
        if (ev && typeof ev === "object" && ev.path) {
          codeEvidence.push({
            id: String(ev.id || `ev${codeEvidence.length + 1}`),
            label: String(ev.label || "Evidence"),
            path: String(ev.path),
            startLine: Number(ev.startLine) || 0,
            endLine: ev.endLine ? Number(ev.endLine) : undefined,
            language: String(ev.language || "unknown"),
            role: (["entrypoint", "source", "root_control", "sink", "evidence", "expected_control"].includes(String(ev.role))
              ? String(ev.role)
              : "evidence") as CodeEvidenceItem["role"],
            code: String(ev.code || ""),
            explanation: String(ev.explanation || ""),
          });
        }
      }
    }

    return {
      dataflow: parsed.dataflow || "",
      reachability: parsed.reachability || "",
      impact,
      likelihood,
      severity,
      rationale: parsed.rationale || severity.rationale,
      changeConditions: parsed.changeConditions || "",
      counterevidence: parsed.counterevidence || "",
      proofGaps: parsed.proofGaps || "",
      rootCauseSummary: parsed.rootCauseSummary || "",
      codeEvidence,
    };
  } catch {
    return null;
  }
}

// ─── DB Update Mapper ────────────────────────────────────────────────────────

/**
 * Map AttackPathResult to Prisma Vulnerability update data
 */
export function toVulnerabilityUpdate(result: AttackPathResult): Record<string, unknown> {
  const update: Record<string, unknown> = {
    attackPathDataflow: result.dataflow || null,
    attackPathReachability: result.reachability || null,
    severityRationale: result.rationale || null,
    severityChangeConditions: result.changeConditions || null,
    impactLevel: result.impact,
    likelihoodLevel: result.likelihood,
    counterevidence: result.counterevidence || null,
    proofGaps: result.proofGaps || null,
    rootCauseSummary: result.rootCauseSummary || null,
  };

  if (result.codeEvidence.length > 0) {
    update.codeEvidence = result.codeEvidence;
  }

  // If suppressed, mark as false positive
  if (result.severity.suppressed) {
    update.isFalsePositive = true;
    update.fpReason = `Severity suppressed: ${result.severity.suppressionReason}`;
  } else {
    // Update severity based on calibration
    update.severity = toAetheriaSeverity(result.severity.level);
  }

  return update;
}

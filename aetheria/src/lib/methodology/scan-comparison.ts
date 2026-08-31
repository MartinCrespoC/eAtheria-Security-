/**
 * Cross-Scan Comparison
 * Replicates codex-security scan-comparison SDK feature
 * LLM-based root-cause matching across scans over time
 */

import { prisma } from "@/lib/db";
import { generateText } from "@/lib/ai";
import { ANALYSIS_VOICE, JSON_OUTPUT_CONTRACT, truncateForPrompt } from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScanFindingSummary {
  id: string;
  title: string;
  severity: string;
  cweId?: string | null;
  category?: string;
  filePath?: string | null;
  description?: string;
  fingerprint?: string | null;
  rootCauseSummary?: string | null;
}

export interface ComparisonMatch {
  prevId: string;
  currId: string;
  confidence: "high" | "medium" | "low";
  rationale: string;
}

export interface ComparisonResult {
  matches: ComparisonMatch[];
  uncertain: Array<{ prevId: string; currId: string; reason: string }>;
  resolved: string[];    // prevIds that are fixed (no match in current)
  introduced: string[];  // currIds that are new (no match in previous)
  summary: string;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build cross-scan comparison prompt
 * Match findings by root cause regardless of titles/CWE/fingerprints
 */
export function buildComparisonPrompt(
  previousFindings: ScanFindingSummary[],
  currentFindings: ScanFindingSummary[]
): string {
  const formatFindings = (findings: ScanFindingSummary[]) =>
    findings
      .slice(0, 40)
      .map((f) => {
        const parts = [`[${f.id}] ${f.title} (${f.severity})`];
        if (f.cweId) parts.push(`CWE: ${f.cweId}`);
        if (f.filePath) parts.push(`File: ${f.filePath}`);
        if (f.rootCauseSummary) parts.push(`Root cause: ${f.rootCauseSummary}`);
        else if (f.description) parts.push(`Desc: ${truncateForPrompt(f.description, 150)}`);
        return parts.join(" | ");
      })
      .join("\n");

  return `${ANALYSIS_VOICE}

## Task
Compare findings from two security scans of the same application.
Match findings that share the same ROOT CAUSE, even if their titles, CWE classifications, or file paths differ.
Identify which previous findings are resolved and which current findings are newly introduced.

## Matching Rules
- Match by root cause, NOT by title string similarity
- Same vulnerability class in same code region = likely match
- Different CWE but same underlying code defect = match
- Same CWE in completely different components = NOT a match
- Refactored code that preserves the same defect = match
- Fixed and re-introduced = match (note the regression)

## Previous Scan Findings (${previousFindings.length} total)
${formatFindings(previousFindings)}

## Current Scan Findings (${currentFindings.length} total)
${formatFindings(currentFindings)}

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "matches": [
    {
      "prevId": "vuln-id-from-previous",
      "currId": "vuln-id-from-current",
      "confidence": "high|medium|low",
      "rationale": "Brief explanation of why these are the same root cause"
    }
  ],
  "uncertain": [
    {
      "prevId": "vuln-id",
      "currId": "vuln-id",
      "reason": "Why uncertain"
    }
  ],
  "resolved": ["prev-ids-with-no-current-match"],
  "introduced": ["curr-ids-with-no-previous-match"],
  "summary": "One paragraph summarizing the security posture change between scans"
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

export function parseComparisonResponse(text: string): ComparisonResult | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

    const matches: ComparisonMatch[] = Array.isArray(parsed.matches)
      ? (parsed.matches as Array<Record<string, unknown>>).map((m) => ({
          prevId: String(m.prevId || ""),
          currId: String(m.currId || ""),
          confidence: (["high", "medium", "low"].includes(String(m.confidence))
            ? String(m.confidence)
            : "medium") as "high" | "medium" | "low",
          rationale: String(m.rationale || ""),
        }))
      : [];

    const uncertain = Array.isArray(parsed.uncertain)
      ? (parsed.uncertain as Array<Record<string, unknown>>).map((u) => ({
          prevId: String(u.prevId || ""),
          currId: String(u.currId || ""),
          reason: String(u.reason || ""),
        }))
      : [];

    const resolved = Array.isArray(parsed.resolved)
      ? (parsed.resolved as unknown[]).map(String)
      : [];

    const introduced = Array.isArray(parsed.introduced)
      ? (parsed.introduced as unknown[]).map(String)
      : [];

    return {
      matches,
      uncertain,
      resolved,
      introduced,
      summary: String(parsed.summary || ""),
    };
  } catch {
    return null;
  }
}

// ─── Core Comparison Function ────────────────────────────────────────────────

/**
 * Compare two scans using LLM-based root-cause matching
 * Falls back to fingerprint-only matching if AI is unavailable
 */
export async function compareScans(
  prevAnalysisId: string,
  currAnalysisId: string,
  companyId?: string
): Promise<ComparisonResult | null> {
  // Load findings from both scans
  const [prevFindings, currFindings] = await Promise.all([
    prisma.vulnerability.findMany({
      where: { analysisId: prevAnalysisId, isFalsePositive: false },
      select: {
        id: true,
        title: true,
        severity: true,
        cweId: true,
        category: true,
        filePath: true,
        description: true,
        fingerprint: true,
        rootCauseSummary: true,
      },
      take: 100,
    }),
    prisma.vulnerability.findMany({
      where: { analysisId: currAnalysisId, isFalsePositive: false },
      select: {
        id: true,
        title: true,
        severity: true,
        cweId: true,
        category: true,
        filePath: true,
        description: true,
        fingerprint: true,
        rootCauseSummary: true,
      },
      take: 100,
    }),
  ]);

  if (prevFindings.length === 0 && currFindings.length === 0) return null;

  // First pass: exact fingerprint matching (deterministic, no AI needed)
  const fingerprintMatches: ComparisonMatch[] = [];
  const unmatchedPrev: ScanFindingSummary[] = [];
  const unmatchedCurr = [...currFindings] as ScanFindingSummary[];

  for (const prev of prevFindings) {
    if (prev.fingerprint) {
      const currIdx = unmatchedCurr.findIndex((c) => c.fingerprint === prev.fingerprint);
      if (currIdx !== -1) {
        fingerprintMatches.push({
          prevId: prev.id,
          currId: unmatchedCurr[currIdx].id,
          confidence: "high",
          rationale: "Exact fingerprint match",
        });
        unmatchedCurr.splice(currIdx, 1);
        continue;
      }
    }
    unmatchedPrev.push(prev as ScanFindingSummary);
  }

  // If no unmatched findings or no companyId for AI, return fingerprint results
  if (unmatchedPrev.length === 0 || unmatchedCurr.length === 0 || !companyId) {
    return {
      matches: fingerprintMatches,
      uncertain: [],
      resolved: unmatchedPrev.map((f) => f.id),
      introduced: unmatchedCurr.map((f) => f.id),
      summary: `Fingerprint comparison: ${fingerprintMatches.length} matched, ${unmatchedPrev.length} resolved, ${unmatchedCurr.length} introduced.`,
    };
  }

  // Second pass: LLM-based root-cause matching for uncertain findings
  const prompt = buildComparisonPrompt(unmatchedPrev, unmatchedCurr);

  try {
    const response = await generateText(prompt, {
      temperature: 0.1,
      maxOutputTokens: 3000,
      companyId,
    });

    const aiResult = parseComparisonResponse(response?.text || "");

    if (aiResult) {
      // Merge fingerprint matches with AI matches
      return {
        matches: [...fingerprintMatches, ...aiResult.matches],
        uncertain: aiResult.uncertain,
        resolved: aiResult.resolved,
        introduced: aiResult.introduced,
        summary: aiResult.summary,
      };
    }
  } catch (err) {
    console.error(`Scan comparison AI failed (falling back to fingerprint):`, err);
  }

  // Fallback: return fingerprint-only results
  return {
    matches: fingerprintMatches,
    uncertain: [],
    resolved: unmatchedPrev.map((f) => f.id),
    introduced: unmatchedCurr.map((f) => f.id),
    summary: `Fingerprint-only comparison (AI unavailable): ${fingerprintMatches.length} matched, ${unmatchedPrev.length} potentially resolved, ${unmatchedCurr.length} potentially new.`,
  };
}

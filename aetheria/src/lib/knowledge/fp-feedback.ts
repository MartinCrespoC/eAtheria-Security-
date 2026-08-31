/**
 * FP Feedback Loop — closes the learning cycle.
 *
 * When a user manually marks a vulnerability as a false positive (the "last
 * resort" path, since the deterministic detector + AI prompt should already
 * filter the known ones), we capture that knowledge as a *candidate* pattern
 * so the system can learn from it.
 *
 * Safety guarantees:
 *  - Candidates are created `isActive: false` → they NEVER affect detection
 *    until a system admin reviews and activates them in the FP manager UI.
 *  - `confidence` is set low (60) so even an accidentally-activated candidate
 *    stays below every scan-level threshold (STATIC 70 / L2 80 / DEEP 90).
 *  - Idempotent: deduped via `@@unique([source, sourceRuleId])` so marking the
 *    same finding twice does not create duplicates.
 */
import { createHash } from "crypto";
import { prisma } from "@/lib/db";

const EXT_TO_LANG: Record<string, string> = {
  ".ts": "javascript",
  ".tsx": "javascript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".py": "python",
  ".java": "java",
  ".go": "go",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".c": "c",
  ".cpp": "cpp",
  ".rs": "rust",
  ".kt": "kotlin",
  ".scala": "scala",
  ".swift": "swift",
  ".pl": "perl",
  ".lua": "lua",
  ".r": "r",
  ".dart": "dart",
  ".ex": "elixir",
  ".exs": "elixir",
};

/** Candidate confidence: deliberately below the lowest scan threshold (70). */
const MANUAL_CANDIDATE_CONFIDENCE = 60;

export interface ManualFpInput {
  cweId?: string | null;
  category?: string | null;
  title?: string | null;
  filePath?: string | null;
  codeSnippet?: string | null;
  fpReason?: string | null;
}

export interface ManualFpResult {
  created: boolean;
  patternId?: string;
  sourceRuleId: string;
  reason: string;
}

function inferLanguage(filePath?: string | null): string {
  if (!filePath) return "*";
  const dot = filePath.lastIndexOf(".");
  if (dot === -1) return "*";
  return EXT_TO_LANG[filePath.slice(dot).toLowerCase()] || "*";
}

/** Escape a string so it can be used as a literal regex fragment. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a conservative, literal-ish regex from the most representative line of
 * the snippet. This is intentionally specific (safe) — an admin generalizes it
 * during review. Whitespace runs are relaxed to `\s+` for minor resilience.
 */
function derivePattern(snippet: string): string {
  const lines = snippet
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("//") && !l.startsWith("#") && !l.startsWith("*"));
  const core = (lines.sort((a, b) => b.length - a.length)[0] || snippet.trim()).slice(0, 200);
  return escapeRegex(core).replace(/\\?\s+/g, "\\s+");
}

function shortHash(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 12);
}

/**
 * Persist a reviewable manual FP candidate learned from a user-marked finding.
 * Returns `created: false` (with reason) when there is not enough signal or the
 * candidate already exists.
 */
export async function recordManualFalsePositiveCandidate(input: ManualFpInput): Promise<ManualFpResult> {
  const snippet = (input.codeSnippet || "").trim();
  const cweId = input.cweId || "CWE-0";

  if (snippet.length < 8) {
    return { created: false, sourceRuleId: "", reason: "snippet-too-short" };
  }

  const language = inferLanguage(input.filePath);
  const pattern = derivePattern(snippet);
  // Dedup by CWE + normalized code so the same FP marked twice is idempotent.
  const sourceRuleId = `manual-${cweId}-${shortHash(`${language}|${pattern}`)}`;

  try {
    const saved = await prisma.falsePositivePattern.upsert({
      where: { source_sourceRuleId: { source: "manual", sourceRuleId } },
      update: {
        // Do NOT flip isActive on update — keep it reviewable; just refresh context.
        examples: [snippet.slice(0, 1000)],
        context: input.fpReason ? `User reason: ${input.fpReason}`.slice(0, 500) : null,
      },
      create: {
        language,
        pattern,
        description: `Manual FP candidate — ${input.title || cweId}`.slice(0, 300),
        reason:
          input.fpReason ||
          "Marked as false positive by a user. Review and generalize the regex before activating.",
        context: input.fpReason ? `User reason: ${input.fpReason}`.slice(0, 500) : null,
        cweIds: [cweId],
        examples: [snippet.slice(0, 1000)],
        source: "manual",
        confidence: MANUAL_CANDIDATE_CONFIDENCE,
        sourceRuleId,
        category: input.category || null,
        isActive: false, // reviewable — admin activates in the FP manager
      },
    });

    return { created: true, patternId: saved.id, sourceRuleId, reason: "ok" };
  } catch (err) {
    console.error("[fp-feedback] Failed to record manual FP candidate:", err);
    return { created: false, sourceRuleId, reason: "db-error" };
  }
}

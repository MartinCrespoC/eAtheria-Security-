/**
 * Shared Prompt Fragments
 * Common voice, rules, and contracts used across all methodology prompts.
 * Replicates codex-security shared-hard-rules.md and voice guidelines.
 */

// ─── Analysis Voice ──────────────────────────────────────────────────────────

/**
 * The analytical voice used in all methodology prompts.
 * Based on codex-security's report-format.md voice guidelines.
 */
export const ANALYSIS_VOICE = `You are a principal security engineer performing rigorous technical analysis.
Write with professional warmth and precision. Be candid about uncertainty.
Use evidence-based reasoning — never claim validation that did not occur.
Separate observed facts from inferences and assumptions.`;

// ─── Hard Rules ──────────────────────────────────────────────────────────────

/**
 * Shared hard rules for all security analysis phases.
 * From codex-security shared-hard-rules.md
 */
export const SHARED_HARD_RULES = `## Hard Rules
- Base all conclusions on repository evidence, not assumptions
- Do not claim a vulnerability exists without a concrete source-to-sink path
- Do not suppress a real finding because a neighboring path is safe
- A safe neighboring path does not prove this path is safe
- Keep phases separate: discovery identifies, validation proves, attack-path calibrates
- Do not let severity bias affect evidence collection
- Record counterevidence honestly — it strengthens credible findings
- If evidence is insufficient, say so explicitly rather than guessing`;

// ─── JSON Output Contract ────────────────────────────────────────────────────

/**
 * Standard JSON output instructions appended to prompts
 */
export const JSON_OUTPUT_CONTRACT = `## Output Requirements
- Respond with valid JSON only, no markdown fences
- All string values must be concise (max 500 chars per field unless specified)
- Use null for unknown/unavailable fields, never empty strings
- Arrays may be empty but never null
- Do not include comments in JSON`;

// ─── Evidence Classification ─────────────────────────────────────────────────

/**
 * Evidence strength classification for prompt context
 */
export const EVIDENCE_STRENGTH_GUIDE = `## Evidence Strength
- DIRECT: Code explicitly shows the vulnerable path (strongest)
- INFERRED: Logical deduction from code structure
- ANALOGOUS: Based on similar patterns elsewhere
- HYPOTHETICAL: Theoretical, no supporting code evidence (weakest)

Always classify your evidence. Prefer fewer high-strength claims over many weak ones.`;

// ─── Source/Control/Sink Framework ───────────────────────────────────────────

/**
 * The source/control/sink analysis framework used across all phases.
 * From codex-security static-finding-assessment.md
 */
export const SOURCE_CONTROL_SINK_FRAMEWORK = `## Source → Control → Sink Analysis
For each finding, establish:
1. SOURCE: Where attacker-controlled input enters (HTTP param, file upload, DB record, etc.)
2. CONTROL: What security check should protect the path (validation, authz, sanitization)
3. SINK: The dangerous operation reached (exec, query, file write, render, etc.)

Then assess:
- Is the source genuinely attacker-controlled?
- Is the control absent, bypassed, mis-scoped, or incomplete?
- Does the sink produce concrete security impact?
- What counterevidence exists (sanitizers, guards, type constraints)?
- What proof gaps remain (runtime config, deployment specifics)?`;

// ─── Confidence Scale ────────────────────────────────────────────────────────

export const CONFIDENCE_SCALE = `## Confidence Scale
- HIGH: Direct source/config/runtime evidence, no material unresolved blocker
- MEDIUM: Plausible from source evidence, but runtime/deployment/reachability needs proof
- LOW: Weak or incomplete evidence, follow-up candidate only`;

// ─── Utility ─────────────────────────────────────────────────────────────────

/**
 * Truncate text to a max length for token budget management
 */
export function truncateForPrompt(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  return text.slice(0, maxChars) + "\n... [truncated]";
}

/**
 * Format a finding context block for prompt injection
 */
export function formatFindingContext(finding: {
  title: string;
  description: string;
  cweId?: string | null;
  filePath?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
  codeSnippet?: string | null;
  severity?: string;
  category?: string;
}): string {
  const parts: string[] = [
    `Title: ${finding.title}`,
    `Category: ${finding.category || "Unknown"}`,
    `CWE: ${finding.cweId || "Unknown"}`,
    `Severity: ${finding.severity || "Unassessed"}`,
    `Location: ${finding.filePath || "Unknown"}${finding.lineStart ? `:${finding.lineStart}${finding.lineEnd ? `-${finding.lineEnd}` : ""}` : ""}`,
    `Description: ${finding.description}`,
  ];

  if (finding.codeSnippet) {
    parts.push(`Code:\n\`\`\`\n${truncateForPrompt(finding.codeSnippet, 1500)}\n\`\`\``);
  }

  return parts.join("\n");
}

/**
 * Severity Calibration Engine
 * Replicates codex-security severity-policy.md knowledge:
 * - Impact × Likelihood → Severity matrix
 * - Hard suppression rules
 * - Priority mapping (P0-P3)
 * - High/Critical acceptance checklist
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImpactLevel = "high" | "medium" | "low" | "ignore";
export type LikelihoodLevel = "high" | "medium" | "low" | "ignore";
export type CalibratedSeverityLevel = "critical" | "high" | "medium" | "low" | "ignore";

export interface SuppressionContext {
  /** Only affects the attacker's own session/data */
  selfOnly?: boolean;
  /** Required precondition cannot realistically be met */
  unachievablePrecondition?: boolean;
  /** Requires admin/root privilege — same as impact target */
  privilegedOnly?: boolean;
  /** Only reachable in test/demo/example code not shipped */
  nonShippedCode?: boolean;
  /** Requires physical access to hardware */
  physicalAccessRequired?: boolean;
}

export interface CalibratedSeverity {
  level: CalibratedSeverityLevel;
  priority: string | null; // P0, P1, P2, P3, or null for ignore
  suppressed: boolean;
  suppressionReason: string | null;
  rationale: string;
}

export interface SeverityCalibrationInput {
  impact: ImpactLevel;
  likelihood: LikelihoodLevel;
  suppressionContext?: SuppressionContext;
  /** Additional context for rationale generation */
  findingTitle?: string;
  cweId?: string;
}

// ─── Severity Matrix ─────────────────────────────────────────────────────────

/**
 * Impact × Likelihood → Final Severity
 * From codex-security severity-policy.md calibration matrix
 */
export const SEVERITY_MATRIX: Record<ImpactLevel, Record<LikelihoodLevel, CalibratedSeverityLevel>> = {
  high: {
    high: "critical",
    medium: "high",
    low: "medium",
    ignore: "ignore",
  },
  medium: {
    high: "high",
    medium: "medium",
    low: "low",
    ignore: "ignore",
  },
  low: {
    high: "medium",
    medium: "low",
    low: "low",
    ignore: "ignore",
  },
  ignore: {
    high: "ignore",
    medium: "ignore",
    low: "ignore",
    ignore: "ignore",
  },
};

// ─── Priority Mapping ────────────────────────────────────────────────────────

/**
 * Severity → Priority mapping for tracking systems
 * critical→P0, high→P1, medium→P2, low→P3
 */
export const SEVERITY_TO_PRIORITY: Record<CalibratedSeverityLevel, string | null> = {
  critical: "P0",
  high: "P1",
  medium: "P2",
  low: "P3",
  ignore: null,
};

// ─── Suppression Rules ───────────────────────────────────────────────────────

interface SuppressionRule {
  key: keyof SuppressionContext;
  result: CalibratedSeverityLevel;
  reason: string;
}

/**
 * Hard suppression rules from codex-security severity-policy.md
 * These override the matrix when conditions are met
 */
export const SUPPRESSION_RULES: SuppressionRule[] = [
  {
    key: "selfOnly",
    result: "ignore",
    reason: "Only affects the attacker's own session/data — no cross-boundary impact",
  },
  {
    key: "unachievablePrecondition",
    result: "ignore",
    reason: "Required precondition cannot be met in any supported deployment",
  },
  {
    key: "privilegedOnly",
    result: "ignore",
    reason: "Requires admin/root privilege — attacker already has equivalent access",
  },
  {
    key: "nonShippedCode",
    result: "ignore",
    reason: "Only reachable in test/demo/example code not included in shipped artifact",
  },
  {
    key: "physicalAccessRequired",
    result: "ignore",
    reason: "Requires physical access to hardware — outside remote threat model",
  },
];

// ─── High/Critical Acceptance Checklist ──────────────────────────────────────

/**
 * Checklist items that MUST be satisfied for high/critical severity
 * From codex-security severity-policy.md acceptance criteria
 */
export const HIGH_CRITICAL_CHECKLIST = [
  "Attacker-controlled input reaches the vulnerable code path",
  "The security boundary crossed is explicitly defined in the threat model",
  "Impact affects other users, data, or system integrity (not self-only)",
  "No complete mitigation exists in the current codebase",
  "The attack does not require unrealistic preconditions",
  "Reachability is demonstrated from a supported entry point",
] as const;

// ─── Impact Assessment Guide ─────────────────────────────────────────────────

export const IMPACT_GUIDE: Record<ImpactLevel, string[]> = {
  high: [
    "Remote code execution",
    "Full database/data breach",
    "Authentication bypass (any user)",
    "Privilege escalation to admin",
    "Complete tenant isolation failure",
    "Arbitrary file write/delete on server",
  ],
  medium: [
    "Stored XSS affecting other users",
    "IDOR exposing sensitive data",
    "CSRF on state-changing operations",
    "Partial authorization bypass",
    "Information disclosure of internal data",
    "Denial of service (resource exhaustion)",
  ],
  low: [
    "Reflected XSS requiring user interaction",
    "Open redirect",
    "Verbose error messages",
    "Missing security headers (non-exploitable)",
    "Self-XSS only",
    "Rate limiting bypass (non-critical)",
  ],
  ignore: [
    "Best-practice recommendations only",
    "Theoretical issues with no attack path",
    "Issues in deprecated/unused code",
    "Documentation-only findings",
  ],
};

// ─── Likelihood Assessment Guide ─────────────────────────────────────────────

export const LIKELIHOOD_GUIDE: Record<LikelihoodLevel, string[]> = {
  high: [
    "No authentication required",
    "Exploitable via simple HTTP request",
    "Public exploit exists",
    "No special configuration needed",
    "Affects default deployment",
  ],
  medium: [
    "Requires authenticated user (any role)",
    "Requires specific but common configuration",
    "Multi-step attack chain",
    "Requires user interaction (click)",
  ],
  low: [
    "Requires admin/special role",
    "Requires non-default configuration",
    "Complex multi-step with race conditions",
    "Requires specific deployment topology",
  ],
  ignore: [
    "Requires physical access",
    "Requires compromised admin account first",
    "Only in development/test mode",
    "Requires impossible preconditions",
  ],
};

// ─── Core Calibration Function ───────────────────────────────────────────────

/**
 * Calibrate severity using the impact×likelihood matrix with suppression rules
 */
export function calibrateSeverity(input: SeverityCalibrationInput): CalibratedSeverity {
  const { impact, likelihood, suppressionContext, findingTitle, cweId } = input;

  // Check suppression rules first
  if (suppressionContext) {
    for (const rule of SUPPRESSION_RULES) {
      if (suppressionContext[rule.key]) {
        return {
          level: rule.result,
          priority: null,
          suppressed: true,
          suppressionReason: rule.reason,
          rationale: `Suppressed: ${rule.reason}`,
        };
      }
    }
  }

  // Apply matrix
  const level = SEVERITY_MATRIX[impact][likelihood];
  const priority = SEVERITY_TO_PRIORITY[level];

  // Build rationale
  const contextParts: string[] = [];
  if (findingTitle) contextParts.push(`"${findingTitle}"`);
  if (cweId) contextParts.push(`(${cweId})`);
  const context = contextParts.length > 0 ? ` ${contextParts.join(" ")}` : "";

  const rationale =
    level === "ignore"
      ? `No actionable risk: impact=${impact}, likelihood=${likelihood}`
      : `Calibrated${context}: impact=${impact} × likelihood=${likelihood} → ${level} (${priority})`;

  return {
    level,
    priority,
    suppressed: false,
    suppressionReason: null,
    rationale,
  };
}

// ─── AI Prompt Builder ───────────────────────────────────────────────────────

/**
 * Build a prompt for AI to assess impact and likelihood of a finding
 * Used when we need the LLM to determine impact/likelihood before calibration
 */
export function buildSeverityAssessmentPrompt(
  finding: {
    title: string;
    description: string;
    cweId?: string;
    filePath?: string;
    codeSnippet?: string;
    severity?: string;
  },
  threatModelContext?: string
): string {
  return `You are a security analyst calibrating vulnerability severity using a structured methodology.

## Task
Assess the IMPACT and LIKELIHOOD of this finding, then determine final severity.

## Finding
- Title: ${finding.title}
- CWE: ${finding.cweId || "Unknown"}
- File: ${finding.filePath || "Unknown"}
- Description: ${finding.description}
${finding.codeSnippet ? `- Code:\n\`\`\`\n${finding.codeSnippet.slice(0, 1000)}\n\`\`\`` : ""}

${threatModelContext ? `## Threat Model Context\n${threatModelContext.slice(0, 2000)}` : ""}

## Impact Levels
- **high**: RCE, full data breach, auth bypass (any user), privilege escalation to admin, tenant isolation failure
- **medium**: Stored XSS, IDOR with sensitive data, CSRF on state changes, partial authz bypass, DoS
- **low**: Reflected XSS (user interaction), open redirect, verbose errors, missing headers
- **ignore**: Best-practice only, theoretical, deprecated code, documentation

## Likelihood Levels
- **high**: No auth required, simple HTTP request, public exploit, default deployment affected
- **medium**: Requires any authenticated user, common config, multi-step, user interaction needed
- **low**: Requires admin role, non-default config, complex race condition, specific topology
- **ignore**: Physical access, compromised admin first, dev/test mode only, impossible preconditions

## Suppression Rules (apply if any match)
- self_only: Only affects attacker's own session → ignore
- unachievable_precondition: Required precondition cannot be met → ignore
- privileged_only: Requires same privilege as impact target → ignore
- non_shipped_code: Only in test/demo/example code → ignore

## Response Format (JSON only)
{
  "impact": "high|medium|low|ignore",
  "likelihood": "high|medium|low|ignore",
  "suppressed": false,
  "suppressionReason": null,
  "rationale": "One sentence explaining the calibration",
  "changeConditions": "What evidence would raise or lower this severity"
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

export interface SeverityAssessmentResult {
  impact: ImpactLevel;
  likelihood: LikelihoodLevel;
  suppressed: boolean;
  suppressionReason: string | null;
  rationale: string;
  changeConditions: string;
  calibrated: CalibratedSeverity;
}

/**
 * Parse AI severity assessment response and apply calibration matrix
 */
export function parseSeverityAssessment(text: string): SeverityAssessmentResult | null {
  try {
    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as {
      impact?: string;
      likelihood?: string;
      suppressed?: boolean;
      suppressionReason?: string;
      rationale?: string;
      changeConditions?: string;
    };

    const impact = (["high", "medium", "low", "ignore"].includes(parsed.impact || "")
      ? parsed.impact
      : "medium") as ImpactLevel;
    const likelihood = (["high", "medium", "low", "ignore"].includes(parsed.likelihood || "")
      ? parsed.likelihood
      : "medium") as LikelihoodLevel;

    const suppressionContext: SuppressionContext = {};
    if (parsed.suppressed && parsed.suppressionReason) {
      // Map AI suppression reason to our context
      const reason = parsed.suppressionReason.toLowerCase();
      if (reason.includes("self")) suppressionContext.selfOnly = true;
      else if (reason.includes("precondition")) suppressionContext.unachievablePrecondition = true;
      else if (reason.includes("privilege") || reason.includes("admin")) suppressionContext.privilegedOnly = true;
      else if (reason.includes("test") || reason.includes("demo")) suppressionContext.nonShippedCode = true;
    }

    const calibrated = calibrateSeverity({ impact, likelihood, suppressionContext });

    return {
      impact,
      likelihood,
      suppressed: calibrated.suppressed,
      suppressionReason: calibrated.suppressionReason,
      rationale: parsed.rationale || calibrated.rationale,
      changeConditions: parsed.changeConditions || "",
      calibrated,
    };
  } catch {
    return null;
  }
}

/**
 * Map calibrated severity level to EATHERIA's Severity enum
 */
export function toAetheriaSeverity(level: CalibratedSeverityLevel): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  switch (level) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH";
    case "medium": return "MEDIUM";
    case "low": return "LOW";
    case "ignore": return "INFO";
  }
}

/**
 * Validation Methodology & Rubric
 * Replicates codex-security validation-guidance.md + static-finding-assessment.md
 * Method-ranked evidence hierarchy and confidence calibration
 */

import {
  ANALYSIS_VOICE,
  JSON_OUTPUT_CONTRACT,
  SOURCE_CONTROL_SINK_FRAMEWORK,
  formatFindingContext,
  truncateForPrompt,
} from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ValidationMethod =
  | "crash_poc"
  | "valgrind_asan"
  | "debugger_trace"
  | "unit_test"
  | "interface_repro"
  | "code_understanding";

export type ValidationDisposition = "reportable" | "suppressed" | "not_applicable" | "deferred";

export interface ValidationMethodDef {
  method: ValidationMethod;
  strength: number; // 0.0 - 1.0
  description: string;
  whenToUse: string;
}

export interface RubricCriterion {
  id: number;
  description: string;
  met: boolean;
  evidence: string;
}

export interface ValidationResult {
  method: ValidationMethod;
  disposition: ValidationDisposition;
  confidence: number; // 0.0 - 1.0
  confidenceLabel: "high" | "medium" | "low";
  rubric: RubricCriterion[];
  evidence: string;
  counterevidence: string;
  proofGaps: string;
  remainingUncertainty: string;
}

// ─── Validation Method Hierarchy ─────────────────────────────────────────────

/**
 * Validation methods ranked by evidence strength
 * From codex-security validation-guidance.md
 */
export const VALIDATION_METHODS: ValidationMethodDef[] = [
  {
    method: "crash_poc",
    strength: 1.0,
    description: "Crashing proof-of-concept demonstrating the vulnerability",
    whenToUse: "Memory corruption, parser confusion, denial-of-service candidates where project can be built",
  },
  {
    method: "valgrind_asan",
    strength: 0.9,
    description: "Memory sanitizer (valgrind/ASan) evidence of unsafe access",
    whenToUse: "Memory-safety or crash candidate that does not immediately reproduce",
  },
  {
    method: "debugger_trace",
    strength: 0.8,
    description: "Non-interactive debugger trace showing source-to-sink path",
    whenToUse: "Runtime execution available but chain is unclear",
  },
  {
    method: "unit_test",
    strength: 0.7,
    description: "Focused regression test exercising the vulnerable code",
    whenToUse: "Vulnerable path covered by existing test harness",
  },
  {
    method: "interface_repro",
    strength: 0.6,
    description: "Minimal end-to-end reproduction through real interface (HTTP, CLI, API)",
    whenToUse: "Code exposes a real user-reachable interface",
  },
  {
    method: "code_understanding",
    strength: 0.3,
    description: "Static code trace: source, control, sink, reachability analysis",
    whenToUse: "Dynamic reproduction not feasible or proportionate",
  },
];

/**
 * Get the base confidence for a validation method
 */
export function getMethodStrength(method: ValidationMethod): number {
  const def = VALIDATION_METHODS.find((m) => m.method === method);
  return def?.strength ?? 0.3;
}

// ─── Confidence Calibration ──────────────────────────────────────────────────

/**
 * Calibrate confidence from validation method + evidence quality
 * Adjusts base method strength by evidence and counterevidence factors
 */
export function calibrateConfidence(
  method: ValidationMethod,
  evidenceQuality: "strong" | "moderate" | "weak",
  hasCounterevidence: boolean,
  proofGapsExist: boolean
): number {
  let confidence = getMethodStrength(method);

  // Adjust for evidence quality
  switch (evidenceQuality) {
    case "strong": confidence += 0.05; break;
    case "moderate": break;
    case "weak": confidence -= 0.1; break;
  }

  // Penalize for counterevidence
  if (hasCounterevidence) confidence -= 0.15;

  // Penalize for proof gaps
  if (proofGapsExist) confidence -= 0.1;

  // Clamp to [0, 1]
  return Math.max(0, Math.min(1, confidence));
}

/**
 * Map numeric confidence to label
 */
export function confidenceToLabel(confidence: number): "high" | "medium" | "low" {
  if (confidence >= 0.7) return "high";
  if (confidence >= 0.4) return "medium";
  return "low";
}

// ─── Rubric Builder ──────────────────────────────────────────────────────────

/**
 * Build a validation rubric (up to 5 criteria) for a finding
 * From codex-security validation-guidance.md instance-preserving rules
 */
export function buildValidationRubric(finding: {
  title: string;
  cweId?: string | null;
  category?: string;
}): RubricCriterion[] {
  const criteria: RubricCriterion[] = [
    {
      id: 1,
      description: "Attacker-controlled input reaches the vulnerable code path",
      met: false,
      evidence: "",
    },
    {
      id: 2,
      description: "The security control is absent, bypassed, or incomplete",
      met: false,
      evidence: "",
    },
    {
      id: 3,
      description: "The dangerous sink produces concrete security impact",
      met: false,
      evidence: "",
    },
    {
      id: 4,
      description: "No complete counterevidence defeats the finding",
      met: false,
      evidence: "",
    },
    {
      id: 5,
      description: "The finding is reachable from a supported entry point in shipped code",
      met: false,
      evidence: "",
    },
  ];

  return criteria;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build validation prompt for AI-assisted finding validation
 */
export function buildValidationPrompt(
  finding: {
    title: string;
    description: string;
    cweId?: string | null;
    filePath?: string | null;
    lineStart?: number | null;
    codeSnippet?: string | null;
    severity?: string;
    category?: string;
  },
  codeContext?: string,
  knowledgeContext?: string
): string {
  return `${ANALYSIS_VOICE}

## Task
Validate this security finding using the strongest available evidence method. Produce a structured validation assessment.

## Finding
${formatFindingContext(finding)}

${codeContext ? `## Code Context\n\`\`\`\n${truncateForPrompt(codeContext, 2000)}\n\`\`\`\n` : ""}
${knowledgeContext ? `${knowledgeContext}\n` : ""}
${SOURCE_CONTROL_SINK_FRAMEWORK}

## Validation Method Hierarchy (strongest first)
1. crash_poc (strength 1.0): Crashing proof-of-concept
2. valgrind_asan (strength 0.9): Memory sanitizer evidence
3. debugger_trace (strength 0.8): Debugger source-to-sink trace
4. unit_test (strength 0.7): Focused regression test
5. interface_repro (strength 0.6): Realistic interface reproduction
6. code_understanding (strength 0.3): Static code trace only

Choose the strongest method feasible for this finding. For static analysis (no runtime), use code_understanding.

## Validation Rubric (assess each)
1. Attacker-controlled input reaches the vulnerable code path
2. The security control is absent, bypassed, or incomplete
3. The dangerous sink produces concrete security impact
4. No complete counterevidence defeats the finding
5. The finding is reachable from a supported entry point in shipped code

## Disposition Rules
- reportable: Evidence supports the finding, no defeating counterevidence
- suppressed: Counterevidence positively defeats the finding
- not_applicable: The vulnerability class does not apply to this code
- deferred: Insufficient evidence to decide, needs runtime proof

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "method": "code_understanding",
  "disposition": "reportable|suppressed|not_applicable|deferred",
  "evidenceQuality": "strong|moderate|weak",
  "rubric": [
    {"id": 1, "description": "...", "met": true, "evidence": "req.body.query flows to db.rawQuery without sanitization"},
    {"id": 2, "description": "...", "met": true, "evidence": "No parameterized query or escaping found"},
    {"id": 3, "description": "...", "met": true, "evidence": "db.rawQuery executes arbitrary SQL"},
    {"id": 4, "description": "...", "met": true, "evidence": "No WAF or input filter identified"},
    {"id": 5, "description": "...", "met": true, "evidence": "POST /api/search is a public endpoint"}
  ],
  "evidence": "Concise summary of supporting evidence",
  "counterevidence": "Arguments against, or 'none identified'",
  "proofGaps": "What remains unproven, or 'none'",
  "remainingUncertainty": "What runtime/deployment info would change the assessment"
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

/**
 * Parse AI validation response
 */
export function parseValidationResponse(text: string): ValidationResult | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as {
      method?: string;
      disposition?: string;
      evidenceQuality?: string;
      rubric?: Array<{ id?: number; description?: string; met?: boolean; evidence?: string }>;
      evidence?: string;
      counterevidence?: string;
      proofGaps?: string;
      remainingUncertainty?: string;
    };

    const method = (VALIDATION_METHODS.some((m) => m.method === parsed.method)
      ? parsed.method
      : "code_understanding") as ValidationMethod;

    const disposition = (["reportable", "suppressed", "not_applicable", "deferred"].includes(parsed.disposition || "")
      ? parsed.disposition
      : "deferred") as ValidationDisposition;

    const evidenceQuality = (["strong", "moderate", "weak"].includes(parsed.evidenceQuality || "")
      ? parsed.evidenceQuality
      : "moderate") as "strong" | "moderate" | "weak";

    const hasCounterevidence = !!parsed.counterevidence &&
      parsed.counterevidence.toLowerCase() !== "none" &&
      parsed.counterevidence.toLowerCase() !== "none identified";
    const proofGapsExist = !!parsed.proofGaps &&
      parsed.proofGaps.toLowerCase() !== "none";

    const confidence = calibrateConfidence(method, evidenceQuality, hasCounterevidence, proofGapsExist);

    // Parse rubric
    const rubric: RubricCriterion[] = [];
    if (Array.isArray(parsed.rubric)) {
      for (const item of parsed.rubric.slice(0, 5)) {
        rubric.push({
          id: item.id || rubric.length + 1,
          description: item.description || "",
          met: !!item.met,
          evidence: item.evidence || "",
        });
      }
    }

    return {
      method,
      disposition,
      confidence,
      confidenceLabel: confidenceToLabel(confidence),
      rubric,
      evidence: parsed.evidence || "",
      counterevidence: parsed.counterevidence || "",
      proofGaps: parsed.proofGaps || "",
      remainingUncertainty: parsed.remainingUncertainty || "",
    };
  } catch {
    return null;
  }
}

// ─── DB Update Mapper ────────────────────────────────────────────────────────

/**
 * Map ValidationResult to Prisma Vulnerability update data
 */
export function toValidationUpdate(result: ValidationResult): Record<string, unknown> {
  return {
    validationMethod: result.method,
    validationEvidence: result.evidence || null,
    validationConfidence: result.confidence,
    counterevidence: result.counterevidence || null,
    proofGaps: result.proofGaps || null,
    aiValidated: true,
    aiConfidence: result.confidence,
    // If suppressed or not_applicable, mark as false positive
    ...(result.disposition === "suppressed" || result.disposition === "not_applicable"
      ? {
          isFalsePositive: true,
          fpReason: `Validation ${result.disposition}: ${result.evidence.slice(0, 200)}`,
        }
      : {}),
  };
}

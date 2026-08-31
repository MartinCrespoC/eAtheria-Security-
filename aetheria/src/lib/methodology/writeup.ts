/**
 * Vulnerability Writeup Generator
 * Replicates codex-security vulnerability-writeup skill + report-format.md
 * Generates disclosure-quality vulnerability reports
 */

import { prisma } from "@/lib/db";
import { generateText } from "@/lib/ai";
import { ANALYSIS_VOICE, truncateForPrompt } from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface WriteupContext {
  title: string;
  description: string;
  severity: string;
  cweId?: string | null;
  filePath?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
  codeSnippet?: string | null;
  category?: string;
  attackPathDataflow?: string | null;
  attackPathReachability?: string | null;
  severityRationale?: string | null;
  rootCauseSummary?: string | null;
  validationMethod?: string | null;
  validationEvidence?: string | null;
  smartFix?: string | null;
  fixExplanation?: string | null;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build vulnerability writeup prompt
 * Structure from codex-security report-format.md
 */
export function buildWriteupPrompt(finding: WriteupContext, fullFileContent?: string): string {
  return `${ANALYSIS_VOICE}

## Task
Write a comprehensive vulnerability writeup suitable for disclosure to the development team.
Use a natural first-person researcher voice. Guide the reader through the vulnerability with "we" language.

## Finding Data
- Title: ${finding.title}
- Severity: ${finding.severity}
- CWE: ${finding.cweId || "Unknown"}
- Category: ${finding.category || "Unknown"}
- Location: ${finding.filePath || "Unknown"}${finding.lineStart ? `:${finding.lineStart}` : ""}
- Description: ${finding.description}
${finding.codeSnippet ? `\n## Vulnerable Code\n\`\`\`\n${truncateForPrompt(finding.codeSnippet, 2000)}\n\`\`\`` : ""}
${fullFileContent ? `\n## Full File Context\n\`\`\`\n${truncateForPrompt(fullFileContent, 3000)}\n\`\`\`` : ""}
${finding.attackPathDataflow ? `\n## Dataflow\n${finding.attackPathDataflow}` : ""}
${finding.attackPathReachability ? `\n## Reachability\n${finding.attackPathReachability}` : ""}
${finding.rootCauseSummary ? `\n## Root Cause\n${finding.rootCauseSummary}` : ""}
${finding.validationEvidence ? `\n## Validation Evidence\nMethod: ${finding.validationMethod}\n${finding.validationEvidence}` : ""}
${finding.smartFix ? `\n## Suggested Fix\n${truncateForPrompt(finding.smartFix, 1500)}` : ""}

## Report Structure (use these exact headings)

### Executive Summary
Summarize the vulnerability, affected component, impact, and validation basis.
State what was inspected vs. what was executed truthfully.

### Background
Technical context: what the component does, its security role, relevant invariants.

### Vulnerability Details
Walk through how the vulnerable code is reached. Prove the bug from source:
entry point → attacker-controlled fields → missed invariant → bad state.
Use short code snippets with file paths. Explain the important lines.

### Exploitability Analysis
How can an attacker maximize impact? Discuss realistic routes, constraints,
and dead ends. This is research, not a verdict.

### Proof of Concept
Describe a minimal reproduction. Include the approach, expected behavior,
and what demonstrates the vulnerability was triggered.

### Remediation
Explain the invariant to restore. Show a minimal fix. Suggest regression tests
and structural improvements to prevent recurrence.

### Summary
Impact, root cause, what was demonstrated, and future research directions.

## Quality Bar
- Source-backed story that proves the vulnerable path
- Short purposeful code snippets, each introduced and explained
- Exploitability explored like research (routes, constraints, dead ends)
- Calm, precise, conversationally professional tone
- Connective reasoning between excerpts and conclusions`;
}

// ─── Generator Function ──────────────────────────────────────────────────────

/**
 * Generate a vulnerability writeup for a specific finding
 */
export async function generateWriteup(
  vulnId: string,
  companyId: string
): Promise<string | null> {
  const vuln = await prisma.vulnerability.findUnique({
    where: { id: vulnId },
    select: {
      title: true,
      description: true,
      severity: true,
      cweId: true,
      filePath: true,
      lineStart: true,
      lineEnd: true,
      codeSnippet: true,
      category: true,
      attackPathDataflow: true,
      attackPathReachability: true,
      severityRationale: true,
      rootCauseSummary: true,
      validationMethod: true,
      validationEvidence: true,
      smartFix: true,
      fixExplanation: true,
    },
  });

  if (!vuln) return null;

  const prompt = buildWriteupPrompt(vuln as WriteupContext);

  try {
    const response = await generateText(prompt, {
      temperature: 0.3,
      maxOutputTokens: 4000,
      companyId,
    });

    return response?.text || null;
  } catch (err) {
    console.error(`Writeup generation failed for vuln ${vulnId}:`, err);
    return null;
  }
}

/**
 * Security Hardening Proposals
 * Replicates codex-security propose-security-hardening skill + proposal-format.md
 * Generates portfolio of structural improvement options with tradeoff analysis
 */

import { prisma } from "@/lib/db";
import { generateText } from "@/lib/ai";
import { ANALYSIS_VOICE, JSON_OUTPUT_CONTRACT, truncateForPrompt } from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FindingSummary {
  title: string;
  severity: string;
  cweId?: string | null;
  category?: string;
  filePath?: string | null;
  description?: string;
}

export interface HardeningOption {
  optionId: string;
  title: string;
  kind: "architectural" | "library" | "process" | "configuration" | "testing";
  summary: string;
  tradeoffs: {
    security: string;
    performance: string;
    memory: string;
    reliability: string;
    operability: string;
    migration: string;
  };
  residualRisks: string;
}

export interface HardeningOpportunity {
  opportunityId: string;
  title: string;
  diagnosis: string;
  options: HardeningOption[];
  recommended: string;
}

export interface HardeningProposalData {
  content: string;
  opportunities: HardeningOpportunity[];
}

// ─── Tradeoff Dimensions ─────────────────────────────────────────────────────

export const TRADEOFF_DIMENSIONS = [
  "security",
  "performance",
  "memory",
  "reliability",
  "operability",
  "migration",
] as const;

export type TradeoffDimension = (typeof TRADEOFF_DIMENSIONS)[number];

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build hardening proposal prompt
 * Portfolio format: opportunities → options → tradeoffs → recommendation
 */
export function buildHardeningPrompt(
  findings: FindingSummary[],
  scanContext: {
    appName: string;
    language: string;
    frameworks?: string[];
    totalFindings: number;
    criticalCount: number;
    highCount: number;
  }
): string {
  const findingsList = findings
    .slice(0, 30)
    .map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.cweId || "N/A"}) — ${f.filePath || "unknown"}`)
    .join("\n");

  return `${ANALYSIS_VOICE}

## Task
Analyze the security findings from this scan and propose a portfolio of structural hardening opportunities.
Each opportunity should present multiple implementation options with honest tradeoff analysis.

## Scan Context
- Application: ${scanContext.appName}
- Primary language: ${scanContext.language}
- Frameworks: ${scanContext.frameworks?.join(", ") || "Unknown"}
- Total findings: ${scanContext.totalFindings} (Critical: ${scanContext.criticalCount}, High: ${scanContext.highCount})

## Findings Summary
${findingsList}

## Proposal Structure
For each hardening opportunity:
1. **Diagnosis**: What structural weakness do the findings reveal?
2. **Options**: 2-4 distinct approaches to address it
3. **Tradeoffs**: Rate each option across 6 dimensions (security, performance, memory, reliability, operability, migration)
4. **Recommendation**: Which option and why

## Tradeoff Rating Scale
For each dimension, use: "improved" | "neutral" | "slight-cost" | "significant-cost"

## Quality Bar
- Opportunities must address ROOT CAUSES, not individual findings
- Options must be genuinely different approaches (not variations of the same fix)
- Tradeoffs must be honest — no option is universally better
- Residual risks must acknowledge what remains even after implementation
- Migration cost must account for existing code, tests, and deployment

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "opportunities": [
    {
      "opportunityId": "OPP-001",
      "title": "Centralize input validation",
      "diagnosis": "Multiple injection findings across endpoints indicate no shared validation layer",
      "options": [
        {
          "optionId": "OPT-A",
          "title": "Schema-first validation (Zod/Yup middleware)",
          "kind": "library",
          "summary": "Add request schema validation at route level",
          "tradeoffs": {
            "security": "improved",
            "performance": "slight-cost",
            "memory": "neutral",
            "reliability": "improved",
            "operability": "neutral",
            "migration": "significant-cost"
          },
          "residualRisks": "Does not cover internal service-to-service calls"
        }
      ],
      "recommended": "OPT-A"
    }
  ]
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

export function parseHardeningResponse(text: string): HardeningOpportunity[] | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as {
      opportunities?: Array<Record<string, unknown>>;
    };

    if (!Array.isArray(parsed.opportunities)) return null;

    return parsed.opportunities.map((opp, idx) => ({
      opportunityId: String(opp.opportunityId || `OPP-${String(idx + 1).padStart(3, "0")}`),
      title: String(opp.title || `Opportunity ${idx + 1}`),
      diagnosis: String(opp.diagnosis || ""),
      options: Array.isArray(opp.options)
        ? (opp.options as Array<Record<string, unknown>>).map((opt, oidx) => ({
            optionId: String(opt.optionId || `OPT-${String.fromCharCode(65 + oidx)}`),
            title: String(opt.title || `Option ${String.fromCharCode(65 + oidx)}`),
            kind: (["architectural", "library", "process", "configuration", "testing"].includes(String(opt.kind))
              ? String(opt.kind)
              : "architectural") as HardeningOption["kind"],
            summary: String(opt.summary || ""),
            tradeoffs: {
              security: String((opt.tradeoffs as Record<string, unknown>)?.security || "neutral"),
              performance: String((opt.tradeoffs as Record<string, unknown>)?.performance || "neutral"),
              memory: String((opt.tradeoffs as Record<string, unknown>)?.memory || "neutral"),
              reliability: String((opt.tradeoffs as Record<string, unknown>)?.reliability || "neutral"),
              operability: String((opt.tradeoffs as Record<string, unknown>)?.operability || "neutral"),
              migration: String((opt.tradeoffs as Record<string, unknown>)?.migration || "neutral"),
            },
            residualRisks: String(opt.residualRisks || ""),
          }))
        : [],
      recommended: String(opp.recommended || ""),
    }));
  } catch {
    return null;
  }
}

// ─── Generator Function ──────────────────────────────────────────────────────

/**
 * Generate hardening proposals for an analysis
 */
export async function generateHardeningProposal(
  analysisId: string,
  companyId: string
): Promise<HardeningProposalData | null> {
  // Load analysis context
  const analysis = await prisma.analysis.findUnique({
    where: { id: analysisId },
    include: {
      appVersion: {
        include: { application: { select: { name: true, language: true } } },
      },
    },
  });

  if (!analysis) return null;

  // Load findings summary
  const findings = await prisma.vulnerability.findMany({
    where: { analysisId, isFalsePositive: false },
    select: {
      title: true,
      severity: true,
      cweId: true,
      category: true,
      filePath: true,
      description: true,
    },
    orderBy: { severity: "asc" }, // CRITICAL first (alphabetical)
    take: 50,
  });

  if (findings.length === 0) return null;

  const prompt = buildHardeningPrompt(findings as FindingSummary[], {
    appName: analysis.appVersion.application.name,
    language: analysis.appVersion.application.language || "unknown",
    totalFindings: findings.length,
    criticalCount: findings.filter((f) => f.severity === "CRITICAL").length,
    highCount: findings.filter((f) => f.severity === "HIGH").length,
  });

  try {
    const response = await generateText(prompt, {
      temperature: 0.3,
      maxOutputTokens: 4000,
      companyId,
    });

    const opportunities = parseHardeningResponse(response?.text || "");
    if (!opportunities || opportunities.length === 0) return null;

    const content = response?.text || "";

    // Persist each opportunity
    for (const opp of opportunities) {
      await prisma.hardeningProposal.create({
        data: {
          analysisId,
          companyId,
          title: opp.title,
          opportunityId: opp.opportunityId,
          diagnosis: opp.diagnosis,
          options: opp.options as never,
          recommended: opp.recommended || null,
          content: truncateForPrompt(content, 10000),
        },
      });
    }

    return { content, opportunities };
  } catch (err) {
    console.error(`Hardening proposal generation failed for analysis ${analysisId}:`, err);
    return null;
  }
}

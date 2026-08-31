/**
 * Delta Engine — Scan Comparison & Fingerprinting
 * Compares current scan findings against previous scan to determine:
 * - NEW: Finding not present in previous scan
 * - EXISTING: Finding was present and still is
 * - FIXED: Finding was present before but no longer detected
 * - REOPENED: Finding was previously resolved but reappeared
 *
 * Fingerprint = SHA-256(filePath + cwe + normalized codeSnippet)
 */
import { createHash } from "crypto";
import { prisma } from "@/lib/db";

export interface DeltaResult {
  fingerprint: string;
  deltaStatus: "NEW" | "EXISTING" | "FIXED" | "REOPENED";
}

/**
 * Generate a stable fingerprint for a vulnerability finding.
 * Uses filePath + CWE + first 80 chars of normalized code snippet.
 */
export function generateFingerprint(filePath: string, cwe: string, codeSnippet: string): string {
  const normalized = codeSnippet
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
  const raw = `${filePath}|${cwe}|${normalized}`;
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

/**
 * Compare current findings against the previous scan for the same application.
 * Returns delta status for each fingerprint and marks FIXED vulns in previous scan.
 */
export async function computeDelta(
  applicationId: string,
  currentAnalysisId: string,
  currentFindings: { fingerprint: string; cweId: string; filePath: string }[]
): Promise<Map<string, DeltaResult>> {
  const deltaMap = new Map<string, DeltaResult>();

  // Find the previous completed analysis for this application (not the current one)
  const previousAnalysis = await prisma.analysis.findFirst({
    where: {
      appVersion: { applicationId },
      status: "COMPLETED",
      id: { not: currentAnalysisId },
    },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });

  if (!previousAnalysis) {
    // First scan — everything is NEW
    for (const finding of currentFindings) {
      deltaMap.set(finding.fingerprint, {
        fingerprint: finding.fingerprint,
        deltaStatus: "NEW",
      });
    }
    return deltaMap;
  }

  // Get previous scan's vulnerabilities with fingerprints
  const previousVulns = await prisma.vulnerability.findMany({
    where: { analysisId: previousAnalysis.id },
    select: {
      id: true,
      fingerprint: true,
      cweId: true,
      filePath: true,
      status: true,
    },
  });

  const previousFingerprints = new Map(
    previousVulns
      .filter((v) => v.fingerprint)
      .map((v) => [v.fingerprint!, v])
  );

  const currentFingerprints = new Set(currentFindings.map((f) => f.fingerprint));

  // Classify current findings
  for (const finding of currentFindings) {
    const prev = previousFingerprints.get(finding.fingerprint);

    if (!prev) {
      deltaMap.set(finding.fingerprint, {
        fingerprint: finding.fingerprint,
        deltaStatus: "NEW",
      });
    } else if (prev.status === "RESOLVED" || prev.status === "FALSE_POSITIVE") {
      deltaMap.set(finding.fingerprint, {
        fingerprint: finding.fingerprint,
        deltaStatus: "REOPENED",
      });
    } else {
      deltaMap.set(finding.fingerprint, {
        fingerprint: finding.fingerprint,
        deltaStatus: "EXISTING",
      });
    }
  }

  // Mark FIXED: previous findings not in current scan
  const fixedIds: string[] = [];
  for (const [fp, prevVuln] of previousFingerprints) {
    if (!currentFingerprints.has(fp)) {
      fixedIds.push(prevVuln.id);
    }
  }

  if (fixedIds.length > 0) {
    await prisma.vulnerability.updateMany({
      where: { id: { in: fixedIds } },
      data: { deltaStatus: "FIXED", status: "RESOLVED", resolvedAt: new Date() },
    });
  }

  return deltaMap;
}

/**
 * Get delta summary stats for an analysis.
 */
export async function getDeltaSummary(analysisId: string) {
  const [newCount, existingCount, fixedCount, reopenedCount] = await Promise.all([
    prisma.vulnerability.count({ where: { analysisId, deltaStatus: "NEW" } }),
    prisma.vulnerability.count({ where: { analysisId, deltaStatus: "EXISTING" } }),
    prisma.vulnerability.count({ where: { analysisId, deltaStatus: "FIXED" } }),
    prisma.vulnerability.count({ where: { analysisId, deltaStatus: "REOPENED" } }),
  ]);

  return { new: newCount, existing: existingCount, fixed: fixedCount, reopened: reopenedCount };
}

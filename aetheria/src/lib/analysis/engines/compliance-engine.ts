/**
 * Compliance Mapping Engine
 * Maps vulnerability findings to compliance frameworks using DB-stored mappings.
 * Frameworks: PCI-DSS v4.0, HIPAA, NIST 800-53, ISO 27001:2022, OWASP Top 10, MITRE Top 25
 *
 * All mappings loaded from ComplianceMapping table (dynamic, DB-driven).
 */
import { prisma } from "@/lib/db";

export interface ComplianceResult {
  cwe: string;
  pciDss: string | null;
  hipaa: string | null;
  nist80053: string | null;
  iso27001: string | null;
  owasp2021: string | null;
  owasp2017: string | null;
  mitreTop25: number | null;
}

export interface ComplianceSummary {
  framework: string;
  totalMapped: number;
  criticalCount: number;
  highCount: number;
  controls: string[];
}

/**
 * Load all compliance mappings from DB (cached per scan).
 */
export async function loadComplianceMappings(): Promise<Map<string, ComplianceResult>> {
  const mappings = await prisma.complianceMapping.findMany({
    where: {},
    select: {
      cwe: true,
      pciDss: true,
      hipaa: true,
      nist80053: true,
      iso27001: true,
      owasp2021: true,
      owasp2017: true,
      mitreTop25: true,
    },
  });

  const map = new Map<string, ComplianceResult>();
  for (const m of mappings) {
    map.set(m.cwe, {
      cwe: m.cwe,
      pciDss: m.pciDss,
      hipaa: m.hipaa,
      nist80053: m.nist80053,
      iso27001: m.iso27001,
      owasp2021: m.owasp2021,
      owasp2017: m.owasp2017,
      mitreTop25: m.mitreTop25,
    });
  }
  return map;
}

/**
 * Enrich findings with compliance data.
 */
export function enrichWithCompliance(
  findings: { cwe: string; severity: string }[],
  mappings: Map<string, ComplianceResult>
): { cwe: string; severity: string; compliance: ComplianceResult | null }[] {
  return findings.map((f) => ({
    ...f,
    compliance: mappings.get(f.cwe) || null,
  }));
}

/**
 * Generate compliance summary report for a scan.
 */
export function generateComplianceSummary(
  findings: { cwe: string; severity: string }[],
  mappings: Map<string, ComplianceResult>
): ComplianceSummary[] {
  const frameworks: Record<string, { controls: Set<string>; critical: number; high: number; total: number }> = {
    "PCI-DSS v4.0": { controls: new Set(), critical: 0, high: 0, total: 0 },
    "HIPAA": { controls: new Set(), critical: 0, high: 0, total: 0 },
    "NIST 800-53": { controls: new Set(), critical: 0, high: 0, total: 0 },
    "ISO 27001:2022": { controls: new Set(), critical: 0, high: 0, total: 0 },
    "OWASP Top 10 2021": { controls: new Set(), critical: 0, high: 0, total: 0 },
  };

  for (const finding of findings) {
    const mapping = mappings.get(finding.cwe);
    if (!mapping) continue;

    if (mapping.pciDss) {
      frameworks["PCI-DSS v4.0"].controls.add(mapping.pciDss);
      frameworks["PCI-DSS v4.0"].total++;
      if (finding.severity === "CRITICAL") frameworks["PCI-DSS v4.0"].critical++;
      if (finding.severity === "HIGH") frameworks["PCI-DSS v4.0"].high++;
    }
    if (mapping.hipaa) {
      frameworks["HIPAA"].controls.add(mapping.hipaa);
      frameworks["HIPAA"].total++;
      if (finding.severity === "CRITICAL") frameworks["HIPAA"].critical++;
      if (finding.severity === "HIGH") frameworks["HIPAA"].high++;
    }
    if (mapping.nist80053) {
      frameworks["NIST 800-53"].controls.add(mapping.nist80053);
      frameworks["NIST 800-53"].total++;
      if (finding.severity === "CRITICAL") frameworks["NIST 800-53"].critical++;
      if (finding.severity === "HIGH") frameworks["NIST 800-53"].high++;
    }
    if (mapping.iso27001) {
      frameworks["ISO 27001:2022"].controls.add(mapping.iso27001);
      frameworks["ISO 27001:2022"].total++;
      if (finding.severity === "CRITICAL") frameworks["ISO 27001:2022"].critical++;
      if (finding.severity === "HIGH") frameworks["ISO 27001:2022"].high++;
    }
    if (mapping.owasp2021) {
      frameworks["OWASP Top 10 2021"].controls.add(mapping.owasp2021);
      frameworks["OWASP Top 10 2021"].total++;
      if (finding.severity === "CRITICAL") frameworks["OWASP Top 10 2021"].critical++;
      if (finding.severity === "HIGH") frameworks["OWASP Top 10 2021"].high++;
    }
  }

  return Object.entries(frameworks)
    .filter(([, data]) => data.total > 0)
    .map(([framework, data]) => ({
      framework,
      totalMapped: data.total,
      criticalCount: data.critical,
      highCount: data.high,
      controls: [...data.controls].sort(),
    }));
}

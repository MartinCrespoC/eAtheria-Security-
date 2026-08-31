/**
 * JSON Export — Structured analysis export with full knowledge enrichment.
 */

interface JsonExportData {
  metadata: {
    tool: string;
    version: string;
    generatedAt: string;
    analysisId: string;
    appName: string;
    appVersion: string;
    status: string;
    scanTypes: string[];
    duration: number | null;
  };
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    falsePositives: number;
    riskScore: number;
  };
  findings: JsonFinding[];
  compliance: Record<string, { requirement: string; count: number }[]>;
  sbom?: unknown;
}

interface JsonFinding {
  id: string;
  severity: string;
  confidence: string;
  category: string;
  title: string;
  description: string;
  filePath: string | null;
  lineStart: number | null;
  cweId: string | null;
  cweUrl: string | null;
  cveId: string | null;
  cveUrl: string | null;
  owaspTop10: string | null;
  detectionMethod: string | null;
  deltaStatus: string | null;
  isFalsePositive: boolean;
  status: string;
  rootCause: string | null;
  smartFix: string | null;
  fixExplanation: string | null;
  packageName: string | null;
  packageVersion: string | null;
  ecosystem: string | null;
}

export function generateJsonReport(
  analysis: {
    id: string;
    status: string;
    scanTypes: unknown;
    duration: number | null;
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    falsePositives: number;
    sbomData?: unknown;
    appVersion: { version: string; application: { name: string } };
    vulnerabilities: Record<string, unknown>[];
  },
  complianceData?: Record<string, { requirement: string; count: number }[]>
): string {
  const scanTypes = Array.isArray(analysis.scanTypes) ? analysis.scanTypes as string[] : [];
  const weights: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 };
  const vulns = analysis.vulnerabilities;
  const totalWeight = vulns.reduce((sum, v) => sum + (weights[String(v.severity)] || 0), 0);
  const maxWeight = vulns.length * 10;
  const riskScore = maxWeight > 0 ? Math.min(100, Math.round((totalWeight / maxWeight) * 100)) : 0;

  const exportData: JsonExportData = {
    metadata: {
      tool: "eAtheria Security",
      version: "1.0.0",
      generatedAt: new Date().toISOString(),
      analysisId: analysis.id,
      appName: analysis.appVersion.application.name,
      appVersion: analysis.appVersion.version,
      status: analysis.status,
      scanTypes,
      duration: analysis.duration,
    },
    summary: {
      totalFindings: analysis.totalIssues,
      critical: analysis.criticalCount,
      high: analysis.highCount,
      medium: analysis.mediumCount,
      low: analysis.lowCount,
      info: analysis.infoCount,
      falsePositives: analysis.falsePositives,
      riskScore,
    },
    findings: vulns.map((v) => ({
      id: String(v.id || ""),
      severity: String(v.severity || ""),
      confidence: String(v.confidence || ""),
      category: String(v.category || ""),
      title: String(v.title || ""),
      description: String(v.description || ""),
      filePath: v.filePath ? String(v.filePath) : null,
      lineStart: v.lineStart ? Number(v.lineStart) : null,
      cweId: v.cweId ? String(v.cweId) : null,
      cweUrl: v.cweId ? `https://cwe.mitre.org/data/definitions/${String(v.cweId).replace("CWE-", "")}.html` : null,
      cveId: v.cveId ? String(v.cveId) : null,
      cveUrl: v.cveId ? `https://nvd.nist.gov/vuln/detail/${String(v.cveId)}` : null,
      owaspTop10: v.owaspTop10 ? String(v.owaspTop10) : null,
      detectionMethod: v.detectionMethod ? String(v.detectionMethod) : null,
      deltaStatus: v.deltaStatus ? String(v.deltaStatus) : null,
      isFalsePositive: Boolean(v.isFalsePositive),
      status: String(v.status || "OPEN"),
      rootCause: v.rootCause ? String(v.rootCause) : null,
      smartFix: v.smartFix ? String(v.smartFix) : null,
      fixExplanation: v.fixExplanation ? String(v.fixExplanation) : null,
      packageName: v.packageName ? String(v.packageName) : null,
      packageVersion: v.packageVersion ? String(v.packageVersion) : null,
      ecosystem: v.ecosystem ? String(v.ecosystem) : null,
    })),
    compliance: complianceData || {},
    sbom: analysis.sbomData || undefined,
  };

  return JSON.stringify(exportData, null, 2);
}

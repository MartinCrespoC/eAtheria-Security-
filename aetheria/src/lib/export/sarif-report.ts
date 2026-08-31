/**
 * SARIF v2.1.0 Export (OASIS Standard)
 * Static Analysis Results Interchange Format
 * Compatible with: GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

interface SarifFinding {
  cwe: string;
  category: string;
  severity: string;
  owasp2021: string;
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  confidence: number;
  detectionMethod: string;
}

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations: {
    executionSuccessful: boolean;
    endTimeUtc: string;
  }[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    tags: string[];
    "security-severity": string;
    precision: string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region: { startLine: number; endLine: number; snippet?: { text: string } };
    };
  }[];
  properties: {
    "security-severity": string;
    precision: string;
    tags: string[];
  };
  partialFingerprints?: { primaryLocationLineHash: string };
}

const SEVERITY_TO_LEVEL: Record<string, "error" | "warning" | "note" | "none"> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
  INFO: "none",
};

const SEVERITY_TO_SCORE: Record<string, string> = {
  CRITICAL: "9.0",
  HIGH: "7.0",
  MEDIUM: "5.0",
  LOW: "3.0",
  INFO: "1.0",
};

export function generateSarifReport(
  findings: SarifFinding[],
  options: {
    scanId: string;
    applicationName: string;
    scanLevel: string;
  }
): SarifLog {
  // Build unique rules from findings
  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
    const ruleId = `${finding.cwe}/${finding.category.replace(/\s+/g, "-").toLowerCase()}`;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.category.replace(/\s+/g, ""),
        shortDescription: { text: finding.title },
        fullDescription: { text: `${finding.category} vulnerability (${finding.cwe}). OWASP: ${finding.owasp2021}. Detection: ${finding.detectionMethod}.` },
        helpUri: `https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html`,
        properties: {
          tags: ["security", finding.cwe, finding.owasp2021, finding.detectionMethod],
          "security-severity": SEVERITY_TO_SCORE[finding.severity] || "5.0",
          precision: finding.confidence >= 90 ? "high" : finding.confidence >= 70 ? "medium" : "low",
        },
      });
    }

    const ruleIndex = [...rulesMap.keys()].indexOf(ruleId);

    results.push({
      ruleId,
      ruleIndex,
      level: SEVERITY_TO_LEVEL[finding.severity] || "warning",
      message: { text: finding.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.filePath,
              uriBaseId: "%SRCROOT%",
            },
            region: {
              startLine: finding.lineStart,
              endLine: finding.lineEnd,
              snippet: { text: finding.codeSnippet.slice(0, 500) },
            },
          },
        },
      ],
      properties: {
        "security-severity": SEVERITY_TO_SCORE[finding.severity] || "5.0",
        precision: finding.confidence >= 90 ? "high" : finding.confidence >= 70 ? "medium" : "low",
        tags: [finding.severity, finding.detectionMethod],
      },
      partialFingerprints: {
        primaryLocationLineHash: `${finding.filePath}:${finding.lineStart}:${finding.cwe}`,
      },
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "EATHERIA Security",
            version: "2.0.0",
            informationUri: "https://aetheria.security",
            rules: [...rulesMap.values()],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: new Date().toISOString(),
          },
        ],
      },
    ],
  };
}

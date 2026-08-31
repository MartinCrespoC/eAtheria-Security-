/**
 * SARIF 2.1.0 result writer — emits AETHERIA findings in the OASIS standard
 * Static Analysis Results Interchange Format.
 *
 * Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and the
 * OWASP Benchmark SARIF-based scoring pipeline.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import * as fs from "fs";
import * as path from "path";

export interface SarifFinding {
  cweId: string; // CWE-79
  category: string; // XSS
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  severity: string; // CRITICAL | HIGH | MEDIUM | LOW
  confidence: number; // 0-100
  codeSnippet?: string;
  taintPath?: string[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId?: string };
      region: { startLine: number; endLine: number; snippet?: { text: string } };
    };
  }>;
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: {
          physicalLocation: {
            artifactLocation: { uri: string };
            region: { startLine: number };
          };
          message: { text: string };
        };
      }>;
    }>;
  }>;
  properties?: Record<string, unknown>;
}

function severityToLevel(sev: string): "error" | "warning" | "note" {
  const s = sev.toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "error";
  if (s === "MEDIUM") return "warning";
  return "note";
}

function cweToHelpUri(cwe: string): string {
  const num = cwe.replace(/\D/g, "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

/**
 * Write findings as a SARIF 2.1.0 JSON file.
 * Returns the output path.
 */
export function writeSarif(
  findings: SarifFinding[],
  outDir: string,
  opts: { toolName?: string; toolVersion?: string; runName?: string } = {}
): string {
  const toolName = opts.toolName ?? "AETHERIA Security";
  const toolVersion = opts.toolVersion ?? "1.0.0";

  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outPath = path.join(outDir, `AETHERIA-${stamp}.sarif`);

  // Build unique rules from findings
  const ruleMap = new Map<string, SarifRule>();
  for (const f of findings) {
    if (!ruleMap.has(f.cweId)) {
      ruleMap.set(f.cweId, {
        id: f.cweId,
        name: f.category.replace(/\s+/g, ""),
        shortDescription: { text: `${f.category} (${f.cweId})` },
        fullDescription: { text: `${f.category} vulnerability detected by AETHERIA taint/weakness analysis. ${f.cweId}.` },
        helpUri: cweToHelpUri(f.cweId),
        properties: {
          tags: ["security", f.category.toLowerCase(), f.cweId],
          "security-severity": String(f.confidence),
        },
      });
    }
  }
  const rules = [...ruleMap.values()];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  // Build results
  const results: SarifResult[] = findings.map((f) => {
    const result: SarifResult = {
      ruleId: f.cweId,
      ruleIndex: ruleIndex.get(f.cweId) ?? 0,
      level: severityToLevel(f.severity),
      message: { text: f.description || f.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.filePath, uriBaseId: "%SRCROOT%" },
            region: {
              startLine: f.lineStart,
              endLine: f.lineEnd,
              ...(f.codeSnippet ? { snippet: { text: f.codeSnippet } } : {}),
            },
          },
        },
      ],
      properties: {
        confidence: f.confidence,
        category: f.category,
      },
    };

    // Add taint path as codeFlow if available
    if (f.taintPath && f.taintPath.length > 0) {
      result.codeFlows = [
        {
          threadFlows: [
            {
              locations: f.taintPath.map((step, i) => ({
                location: {
                  physicalLocation: {
                    artifactLocation: { uri: f.filePath },
                    region: { startLine: f.lineStart + i },
                  },
                  message: { text: step },
                },
              })),
            },
          ],
        },
      ];
    }

    return result;
  });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: toolVersion,
            semanticVersion: toolVersion,
            informationUri: "https://aetheria.security",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            commandLine: `aetheria scan --run=${opts.runName ?? "benchmark"}`,
          },
        ],
        originalUriBaseIds: {
          "%SRCROOT%": { uri: "file:///" },
        },
      },
    ],
  };

  fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2) + "\n");
  return outPath;
}

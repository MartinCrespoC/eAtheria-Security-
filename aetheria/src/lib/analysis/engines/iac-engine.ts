/**
 * Infrastructure as Code (IaC) Scanning Engine
 * Detects security misconfigurations in Terraform, Dockerfile, Kubernetes, and CloudFormation.
 * Rules based on CIS Benchmarks, AWS Security Best Practices, and NIST 800-190.
 *
 * All rules are loaded from the database (IacRule model).
 */

export interface IacFinding {
  cwe: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  owasp2021: string;
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  confidence: number;
  detectionMethod: "IAC";
}

export interface DbIacRule {
  ruleId: string;
  name: string;
  pattern: string;
  severity: string;
  cwe: string;
  category: string;
  description: string;
  fileTypes: string[];
  framework: string;
}

// ==================== MAIN ENGINE ====================
export function runIacAnalysis(fileContent: string, filePath: string, rules: DbIacRule[]): IacFinding[] {
  const findings: IacFinding[] = [];
  const fileName = filePath.split("/").pop() || "";
  const ext = "." + (fileName.split(".").pop() || "");
  const isDockerfile = fileName.toLowerCase().includes("dockerfile");

  // Determine which rules apply based on file type
  const applicableRules = rules.filter((rule) => {
    if (isDockerfile && rule.fileTypes.includes("Dockerfile")) return true;
    return rule.fileTypes.includes(ext);
  });

  if (applicableRules.length === 0) return [];

  // For K8s YAML, only apply K8s rules if it looks like a K8s manifest
  const isK8s = fileContent.includes("apiVersion:") && fileContent.includes("kind:");
  const isCfn = fileContent.includes("AWSTemplateFormatVersion") || fileContent.includes("Resources:");

  const lines = fileContent.split("\n");

  for (const rule of applicableRules) {
    // Skip K8s rules for non-K8s YAML
    if (rule.ruleId.startsWith("k8s-") && !isK8s) continue;
    // Skip CFN rules for non-CFN files
    if (rule.ruleId.startsWith("cfn-") && !isCfn) continue;
    // Skip Docker rules for non-Dockerfiles
    if (rule.ruleId.startsWith("docker-") && !isDockerfile) continue;

    try {
      const regex = new RegExp(rule.pattern, "m");
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          const contextStart = Math.max(0, i - 1);
          const contextEnd = Math.min(lines.length - 1, i + 2);
          const codeSnippet = lines.slice(contextStart, contextEnd + 1).join("\n");

          findings.push({
            cwe: rule.cwe,
            category: rule.category,
            severity: rule.severity as IacFinding["severity"],
            owasp2021: "A05:2021",
            title: `${rule.name} — ${fileName}`,
            description: `${rule.description} [Rule: ${rule.ruleId}]`,
            filePath,
            lineStart: i + 1,
            lineEnd: i + 1,
            codeSnippet,
            confidence: 88,
            detectionMethod: "IAC",
          });
          break; // One finding per rule per file
        }
      }
    } catch {
      // Invalid regex, skip
    }
  }

  // Special check: Dockerfile without USER instruction
  if (isDockerfile) {
    const hasUser = lines.some((l) => /^USER\s+\w+/.test(l.trim()));
    if (!hasUser && lines.some((l) => l.startsWith("FROM"))) {
      findings.push({
        cwe: "CWE-250",
        category: "Privilege Escalation",
        severity: "MEDIUM",
        owasp2021: "A05:2021",
        title: `No USER instruction — ${fileName}`,
        description: "Dockerfile does not specify a USER. Container will run as root by default. Add 'USER nonroot' per CIS Docker 4.1.",
        filePath,
        lineStart: 1,
        lineEnd: lines.length,
        codeSnippet: lines.slice(0, Math.min(5, lines.length)).join("\n"),
        confidence: 80,
        detectionMethod: "IAC",
      });
    }
  }

  return findings;
}

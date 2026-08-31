#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { createServer as createHttpServer } from "node:http";
import { randomUUID } from "node:crypto";
import { z } from "zod";

// ─── Configuration ────────────────────────────────────────────
const AETHERIA_URL = process.env.AETHERIA_URL || "https://aetheria.ikharoz.me";
const AETHERIA_API_KEY = process.env.AETHERIA_API_KEY || "";
const MCP_TRANSPORT = process.env.MCP_TRANSPORT || "stdio"; // stdio | http | all
const MCP_HTTP_PORT = Number(process.env.MCP_HTTP_PORT || 3100);

// Per-request API key: in HTTP mode each client authenticates with its own
// Bearer token (multi-tenant); in stdio mode the env var is used.
const requestContext = new AsyncLocalStorage<{ apiKey?: string }>();
function effectiveApiKey(): string {
  return requestContext.getStore()?.apiKey || AETHERIA_API_KEY;
}

// ─── HTTP Client ──────────────────────────────────────────────
async function apiCall(path: string, options: RequestInit = {}) {
  const url = `${AETHERIA_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${effectiveApiKey()}`,
      ...(options.headers || {}),
    },
  });
  return res;
}

// ─── Library / vendor folder exclusions ───────────────────────
const EXCLUDED_DIRS = [
  "node_modules", ".next", "dist", "build", "out",
  "vendor", "vendors", ".vendor",
  "__pycache__", ".venv", "venv", "env", "site-packages",
  ".git", ".svn", ".hg",
  "target",          // Java/Rust
  "Pods",            // iOS
  ".gradle", ".m2",
  "bower_components",
  ".terraform",
  "coverage", ".nyc_output",
  ".cache", ".parcel-cache",
  "pkg", "bin", "obj", // .NET
];

function isLibraryPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return EXCLUDED_DIRS.some((dir) => {
    const d = dir.toLowerCase();
    return (
      normalized.includes(`/${d}/`) ||
      normalized.startsWith(`${d}/`) ||
      normalized === d
    );
  });
}

/**
 * Recursively zip a local directory (respecting EXCLUDED_DIRS) and return the
 * archive as a base64 string. Used by trigger_repo_scan to send the checked-out
 * repository to the CI/CD scan endpoint so the engine has real source to scan.
 */
async function zipDirectoryToBase64(dirPath: string): Promise<string> {
  const fs = await import("fs/promises");
  const nodePath = await import("path");
  const AdmZip = (await import("adm-zip")).default;

  const root = nodePath.resolve(dirPath);
  const zip = new AdmZip();

  async function walk(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const abs = nodePath.join(current, entry.name);
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.includes(entry.name)) continue;
        await walk(abs);
      } else if (entry.isFile()) {
        const rel = nodePath.relative(root, abs);
        const relDir = nodePath.dirname(rel).split(nodePath.sep).join("/");
        zip.addLocalFile(abs, relDir === "." ? "" : relDir);
      }
    }
  }

  await walk(root);
  return zip.toBuffer().toString("base64");
}

// ─── MCP Server ───────────────────────────────────────────────
const server = new McpServer({
  name: "aetheria-security",
  version: "1.0.0",
});

// ─── Tool: scan_code ──────────────────────────────────────────
server.tool(
  "scan_code",
  "Scan source code for security vulnerabilities using AETHERIA AI-powered SAST engine. " +
    "Detects injection flaws, XSS, authentication issues, hardcoded secrets, cryptographic failures, " +
    "broken access control, and more. Returns vulnerabilities with severity, CWE IDs, OWASP mapping, and AI-generated fixes.",
  {
    code: z.string().describe("Source code to scan for vulnerabilities"),
    language: z
      .string()
      .optional()
      .describe("Programming language (auto-detected if omitted). E.g.: typescript, python, java, go"),
    filePath: z
      .string()
      .optional()
      .describe("File path for context (e.g. src/auth/login.ts)"),
    scanType: z
      .enum(["sast", "sca", "full"])
      .optional()
      .describe("Scan type: 'sast' for source code, 'sca' for dependencies, 'full' for both. Default: sast"),
  },
  async ({ code, language, filePath, scanType }) => {
    if (!effectiveApiKey()) {
      return {
        content: [
          {
            type: "text" as const,
            text: "❌ AETHERIA_API_KEY not configured. Set it in your MCP config environment variables.\n\nGet your API key from: Settings → API Keys in your AETHERIA dashboard.",
          },
        ],
      };
    }

    // Skip library/vendor paths
    if (filePath && isLibraryPath(filePath)) {
      return {
        content: [
          {
            type: "text" as const,
            text: `⚠️ **Skipped:** \`${filePath}\` is inside a library/vendor directory.\nUse SCA (scan_file on package.json/requirements.txt) for dependency scanning.`,
          },
        ],
      };
    }

    try {
      const res = await apiCall("/api/v1/scan/inline", {
        method: "POST",
        body: JSON.stringify({
          code,
          language: language || "auto",
          filePath: filePath || "unknown",
          scanType: scanType || "sast",
          includeExplanation: true,
          includeFix: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [
            {
              type: "text" as const,
              text: `❌ AETHERIA API Error (${res.status}): ${err.error || "Unknown error"}`,
            },
          ],
        };
      }

      const data = await res.json();
      return {
        content: [
          {
            type: "text" as const,
            text: formatScanResults(data, filePath || "unknown"),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown error"}.\nCheck AETHERIA_URL (${AETHERIA_URL}) is accessible.`,
          },
        ],
      };
    }
  }
);

// ─── Tool: scan_file ──────────────────────────────────────────
server.tool(
  "scan_file",
  "Scan a specific file for security vulnerabilities. Provide the file path and the tool will read " +
    "and analyze it. Supports all major languages and dependency files (package.json, requirements.txt, etc.).",
  {
    filePath: z.string().describe("Absolute path to the file to scan"),
    scanType: z
      .enum(["sast", "sca", "full"])
      .optional()
      .describe("Scan type: 'sast' for source, 'sca' for dependencies, 'full' for both"),
  },
  async ({ filePath, scanType }) => {
    if (!effectiveApiKey()) {
      return {
        content: [
          {
            type: "text" as const,
            text: "❌ AETHERIA_API_KEY not configured.",
          },
        ],
      };
    }

    // Block library/vendor paths
    if (isLibraryPath(filePath)) {
      return {
        content: [
          {
            type: "text" as const,
            text: `⚠️ **Skipped:** \`${filePath}\` is inside a library/vendor directory.\n\nAETHERIA skips dependency folders (node_modules, vendor, __pycache__, etc.) for SAST scanning.\nDependency vulnerabilities are detected via **SCA** (Software Composition Analysis) using Google OSV.\n\nTo scan dependencies, use \`scan_file\` on the manifest file (package.json, requirements.txt, etc.) with \`scanType: "sca"\`.`,
          },
        ],
      };
    }

    try {
      const fs = await import("fs/promises");
      const code = await fs.readFile(filePath, "utf-8");

      // Auto-detect scan type for dependency files
      const fileName = filePath.split(/[/\\]/).pop() || "";
      const depFiles = [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
        "Gemfile", "Gemfile.lock", "go.mod", "go.sum",
        "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle",
        "composer.json", "composer.lock",
      ];
      const effectiveScanType = scanType || (depFiles.includes(fileName) ? "sca" : "sast");

      const res = await apiCall("/api/v1/scan/inline", {
        method: "POST",
        body: JSON.stringify({
          code,
          filePath,
          scanType: effectiveScanType,
          includeExplanation: true,
          includeFix: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [
            {
              type: "text" as const,
              text: `❌ AETHERIA API Error (${res.status}): ${err.error || "Unknown error"}`,
            },
          ],
        };
      }

      const data = await res.json();
      return {
        content: [
          {
            type: "text" as const,
            text: formatScanResults(data, filePath),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `❌ Error: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
      };
    }
  }
);

// ─── Tool: get_scan_status ────────────────────────────────────
server.tool(
  "get_scan_status",
  "Get the status and results of a previously triggered scan by its analysis ID.",
  {
    analysisId: z.string().describe("The analysis ID returned from a previous scan"),
  },
  async ({ analysisId }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    try {
      const res = await apiCall(`/api/v1/scan/${analysisId}`);
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [
            { type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` },
          ],
        };
      }

      const data = await res.json();
      let text = `## Scan Status: ${data.status}\n`;
      text += `**Repository:** ${data.repository}\n`;
      text += `**Branch:** ${data.branch}\n`;
      if (data.commit) text += `**Commit:** ${data.commit}\n`;
      if (data.summary) {
        text += `\n### Summary\n`;
        text += `| Severity | Count |\n|---|---|\n`;
        text += `| 🔴 Critical | ${data.summary.critical} |\n`;
        text += `| 🟠 High | ${data.summary.high} |\n`;
        text += `| 🟡 Medium | ${data.summary.medium} |\n`;
        text += `| 🔵 Low | ${data.summary.low} |\n`;
        text += `| ⚪ Info | ${data.summary.info} |\n`;
        text += `| **Total** | **${data.summary.total}** |\n`;
      }

      if (data.vulnerabilities?.length > 0) {
        text += `\n### Vulnerabilities\n`;
        for (const v of data.vulnerabilities) {
          text += `\n#### ${severityIcon(v.severity)} [${v.severity}] ${v.title}\n`;
          if (v.file) text += `📄 ${v.file}${v.line ? `:${v.line}` : ""}\n`;
          if (v.cweId) text += `🏷️ ${v.cweId}\n`;
          text += `${v.description}\n`;
          if (v.fix) text += `\n**Fix:**\n\`\`\`\n${v.fix}\n\`\`\`\n`;
        }
      }

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return {
        content: [
          { type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` },
        ],
      };
    }
  }
);

// ─── Tool: trigger_repo_scan ──────────────────────────────────
server.tool(
  "trigger_repo_scan",
  "Trigger a full repository scan (SAST + SCA) via the AETHERIA CI/CD API. " +
    "Provide projectPath (the checked-out repo on disk) to zip and upload the source so real findings are produced. " +
    "Returns an analysis ID you can poll with get_scan_status.",
  {
    repository: z.string().describe("Repository name, e.g. 'owner/repo'"),
    projectPath: z
      .string()
      .optional()
      .describe(
        "Absolute path to the checked-out repository on disk. If provided, the directory is zipped (excluding library/vendor folders) and its source code is sent to the scanner."
      ),
    branch: z.string().optional().describe("Branch to scan. Default: main"),
    commit: z.string().optional().describe("Commit hash"),
    scanTypes: z
      .array(z.enum(["sast", "sca", "dast"]))
      .optional()
      .describe("Scan types to run. Default: ['sast', 'sca']"),
    aiValidation: z
      .boolean()
      .optional()
      .describe("AI triage of findings with project context (probable-FP review with citable evidence). Default: true"),
  },
  async ({ repository, projectPath, branch, commit, scanTypes, aiValidation }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    try {
      const payload: Record<string, unknown> = {
        repository,
        branch: branch || "main",
        commit: commit || undefined,
        scanTypes: scanTypes || ["sast", "sca"],
        aiValidation: aiValidation !== false,
      };

      // If a local checkout is provided, package it and send the source so the
      // analysis engine actually has code to scan (otherwise the scan is empty).
      let sourceSent = false;
      if (projectPath) {
        try {
          payload.code = await zipDirectoryToBase64(projectPath);
          sourceSent = true;
        } catch (zipErr) {
          return {
            content: [
              {
                type: "text" as const,
                text: `❌ Failed to package '${projectPath}': ${zipErr instanceof Error ? zipErr.message : "Unknown error"}`,
              },
            ],
          };
        }
      }

      const res = await apiCall("/api/v1/scan", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [
            { type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` },
          ],
        };
      }

      const data = await res.json();
      return {
        content: [
          {
            type: "text" as const,
            text: `✅ **Scan triggered successfully!**\n\n` +
              `**Analysis ID:** \`${data.id}\`\n` +
              `**Status:** ${data.status}\n` +
              `**Repository:** ${data.repository}\n` +
              `**Branch:** ${data.branch}\n` +
              `**Scan types:** ${data.scanTypes.join(", ")}\n` +
              `**Source uploaded:** ${sourceSent ? "yes" : "no (metadata only — pass projectPath to scan actual code)"}\n\n` +
              `Use \`get_scan_status\` with ID \`${data.id}\` to check results.`,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          { type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` },
        ],
      };
    }
  }
);

// ─── Tool: explain_vulnerability ──────────────────────────────
server.tool(
  "explain_vulnerability",
  "Get a detailed security explanation for a CWE ID, including its compliance mapping " +
    "(OWASP, PCI-DSS, HIPAA, NIST, ISO 27001) and MITRE rank. Knowledge is served from the AETHERIA database.",
  {
    cweId: z
      .string()
      .optional()
      .describe("CWE ID, e.g. CWE-79, CWE-89 (or just the number, e.g. 79)"),
    vulnerabilityType: z
      .string()
      .optional()
      .describe("Vulnerability type if no CWE is known, e.g. 'SQL Injection', 'XSS'"),
  },
  async ({ cweId, vulnerabilityType }) => {
    const query = cweId || vulnerabilityType;
    if (!query) {
      return {
        content: [
          { type: "text" as const, text: "Please provide either a cweId or vulnerabilityType." },
        ],
      };
    }

    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    // Normalize to a canonical CWE id ("CWE-79"). If the query has no digits it is
    // a free-text vulnerability type, which we cannot resolve to a DB record.
    const digits = query.toUpperCase().replace(/[^0-9]/g, "");
    if (!digits) {
      return {
        content: [
          {
            type: "text" as const,
            text: `## ${query}\nNo CWE ID provided. Look up the matching CWE and call this tool again with its ID.\n\nReference: https://owasp.org/Top10/`,
          },
        ],
      };
    }

    const cwe = `CWE-${digits}`;

    try {
      const res = await apiCall(`/api/v1/cwe/${cwe}`);

      if (res.status === 404) {
        return {
          content: [
            {
              type: "text" as const,
              text: `## ${cwe}\nNo knowledge entry found in the AETHERIA database for this CWE.\n\n🔗 https://cwe.mitre.org/data/definitions/${digits}.html`,
            },
          ],
        };
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [{ type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` }],
        };
      }

      const data = await res.json();
      return { content: [{ type: "text" as const, text: formatCweKnowledge(data) }] };
    } catch (error) {
      return {
        content: [
          { type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` },
        ],
      };
    }
  }
);

// ─── Tool: create_fix_pr ──────────────────────────────────────
server.tool(
  "create_fix_pr",
  "Generate security fix patches for vulnerable files. Sends code + vulnerabilities to AETHERIA AI, " +
    "which returns the fixed code with a unified diff. The AI assistant can then apply the patches " +
    "or create a PR/commit with the fixes.",
  {
    files: z
      .array(
        z.object({
          path: z.string().describe("File path relative to repo root"),
          code: z.string().describe("Current file content"),
          vulnerabilities: z
            .array(
              z.object({
                title: z.string(),
                lineStart: z.number().optional(),
                description: z.string().optional(),
                fix: z.string().optional(),
              })
            )
            .describe("Vulnerabilities to fix in this file"),
        })
      )
      .describe("Array of files with their vulnerabilities to fix"),
    branchName: z.string().optional().describe("Branch name for the fix PR. Default: aetheria/security-fixes"),
    commitMessage: z.string().optional().describe("Commit message for the fixes"),
  },
  async ({ files, branchName, commitMessage }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    if (!files || files.length === 0) {
      return {
        content: [{ type: "text" as const, text: "❌ No files provided. Include files with their vulnerabilities." }],
      };
    }

    try {
      const res = await apiCall("/api/v1/fix-pr", {
        method: "POST",
        body: JSON.stringify({ files, branchName, commitMessage }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [{ type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` }],
        };
      }

      const data = await res.json();

      let text = `## 🔧 AETHERIA Security Fix Patches\n\n`;
      text += `**Total files:** ${data.totalFiles}\n`;
      text += `**Total changes:** ${data.totalChanges}\n`;
      text += `**Branch:** \`${data.branchName}\`\n`;
      text += `**Commit message:** ${data.commitMessage}\n\n`;

      for (const patch of data.patches) {
        text += `### 📄 ${patch.path}\n`;
        text += `**Changes:**\n`;
        for (const change of patch.changes) {
          text += `- ${change}\n`;
        }
        text += `\n**Diff:**\n\`\`\`diff\n${patch.diff}\n\`\`\`\n\n`;
        text += `**Fixed code:**\n\`\`\`\n${patch.fixedCode}\n\`\`\`\n\n---\n\n`;
      }

      text += `\n💡 **To apply:** Use the fixed code above to replace the original files, then commit to branch \`${data.branchName}\` and create a PR.`;

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return {
        content: [
          { type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` },
        ],
      };
    }
  }
);

// ─── Formatting Helpers ───────────────────────────────────────
function severityIcon(severity: string): string {
  switch (severity) {
    case "CRITICAL": return "🔴";
    case "HIGH": return "🟠";
    case "MEDIUM": return "🟡";
    case "LOW": return "🔵";
    case "INFO": return "⚪";
    default: return "⚫";
  }
}

interface CweKnowledge {
  cwe: string;
  name?: string | null;
  mitreRank?: number | null;
  mitreScore?: number | null;
  catalogYear?: number | null;
  compliance?: {
    pciDss?: string | null;
    hipaa?: string | null;
    nist80053?: string | null;
    iso27001?: string | null;
    owasp2021?: string | null;
    owasp2017?: string | null;
    mitreTop25?: number | null;
  };
  references?: { mitre?: string; owasp?: string };
}

function formatCweKnowledge(data: CweKnowledge): string {
  let text = `## ${data.cwe}${data.name ? `: ${data.name}` : ""}\n`;

  if (data.mitreRank) {
    text += `**MITRE Rank:** #${data.mitreRank}`;
    if (data.mitreScore) text += ` (score ${data.mitreScore})`;
    if (data.catalogYear) text += ` — ${data.catalogYear}`;
    text += `\n`;
  }

  const c = data.compliance || {};
  const rows: Array<[string, string]> = [
    ["OWASP 2021", c.owasp2021],
    ["OWASP 2017", c.owasp2017],
    ["PCI-DSS", c.pciDss],
    ["HIPAA", c.hipaa],
    ["NIST 800-53", c.nist80053],
    ["ISO 27001", c.iso27001],
  ].filter((row): row is [string, string] => Boolean(row[1]));

  if (rows.length > 0) {
    text += `\n### Compliance Mapping\n| Framework | Reference |\n|---|---|\n`;
    for (const [framework, ref] of rows) {
      text += `| ${framework} | ${ref} |\n`;
    }
  }

  if (data.references?.mitre) {
    text += `\n🔗 ${data.references.mitre}\n`;
  }

  return text;
}

interface VulnResult {
  severity: string;
  confidence?: string;
  title: string;
  description: string;
  category?: string;
  cweId?: string;
  owasp?: string;
  lineStart?: number;
  lineEnd?: number;
  codeSnippet?: string;
  fix?: string;
  fixExplanation?: string;
  package?: string;
  currentVersion?: string;
  patchedVersion?: string;
}

interface ScanData {
  vulnerabilities: VulnResult[];
  summary: { total: number; critical: number; high: number; medium: number; low: number; info: number };
  language?: string;
  filePath?: string;
  tokensUsed?: { input: number; output: number };
  model?: string;
}

function formatScanResults(data: ScanData, filePath: string): string {
  const { vulnerabilities, summary } = data;

  if (vulnerabilities.length === 0) {
    return `✅ **No vulnerabilities found** in \`${filePath}\`\n\n_Scanned with AETHERIA Security (${data.model || "AI"})_`;
  }

  let text = `## 🛡️ AETHERIA Security Scan Results\n`;
  text += `**File:** \`${filePath}\`\n`;
  if (data.language) text += `**Language:** ${data.language}\n`;
  text += `\n### Summary\n`;
  text += `| Severity | Count |\n|---|---|\n`;
  if (summary.critical > 0) text += `| 🔴 Critical | **${summary.critical}** |\n`;
  if (summary.high > 0) text += `| 🟠 High | **${summary.high}** |\n`;
  if (summary.medium > 0) text += `| 🟡 Medium | ${summary.medium} |\n`;
  if (summary.low > 0) text += `| 🔵 Low | ${summary.low} |\n`;
  if (summary.info > 0) text += `| ⚪ Info | ${summary.info} |\n`;
  text += `| **Total** | **${summary.total}** |\n`;

  text += `\n---\n`;

  for (const v of vulnerabilities) {
    text += `\n### ${severityIcon(v.severity)} [${v.severity}] ${v.title}\n`;
    if (v.category) text += `**Category:** ${v.category}\n`;
    if (v.cweId) text += `**CWE:** ${v.cweId}`;
    if (v.owasp) text += ` | **OWASP:** ${v.owasp}`;
    if (v.cweId || v.owasp) text += `\n`;
    if (v.lineStart) text += `**Line:** ${v.lineStart}${v.lineEnd && v.lineEnd !== v.lineStart ? `-${v.lineEnd}` : ""}\n`;
    if (v.confidence) text += `**Confidence:** ${v.confidence}\n`;
    text += `\n${v.description}\n`;

    if (v.codeSnippet) {
      text += `\n**Vulnerable code:**\n\`\`\`\n${v.codeSnippet}\n\`\`\`\n`;
    }

    if (v.fix) {
      text += `\n**🔧 Fix:**\n\`\`\`\n${v.fix}\n\`\`\`\n`;
      if (v.fixExplanation) text += `_${v.fixExplanation}_\n`;
    }

    if (v.package) {
      text += `\n**Package:** ${v.package}`;
      if (v.currentVersion) text += ` (current: ${v.currentVersion})`;
      if (v.patchedVersion) text += ` → upgrade to ${v.patchedVersion}`;
      text += `\n`;
    }
  }

  text += `\n---\n_Powered by AETHERIA Security • ${data.model || "AI"}_`;
  return text;
}

// ─── Tool: check_owasp_top10 ──────────────────────────────────
server.tool(
  "check_owasp_top10",
  "Analyze code against OWASP Top 10 (2021) vulnerabilities. Returns a compliance report showing which OWASP categories are violated.",
  {
    code: z.string().describe("Source code to analyze"),
    language: z.string().optional().describe("Programming language"),
  },
  async ({ code, language }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    try {
      const res = await apiCall("/api/v1/scan/inline", {
        method: "POST",
        body: JSON.stringify({
          code,
          language: language || "auto",
          scanType: "sast",
          includeExplanation: true,
          includeFix: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [{ type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` }],
        };
      }

      const data = await res.json();
      const owaspMap: Record<string, { title: string; vulns: VulnResult[] }> = {
        "A01:2021": { title: "Broken Access Control", vulns: [] },
        "A02:2021": { title: "Cryptographic Failures", vulns: [] },
        "A03:2021": { title: "Injection", vulns: [] },
        "A04:2021": { title: "Insecure Design", vulns: [] },
        "A05:2021": { title: "Security Misconfiguration", vulns: [] },
        "A06:2021": { title: "Vulnerable and Outdated Components", vulns: [] },
        "A07:2021": { title: "Identification and Authentication Failures", vulns: [] },
        "A08:2021": { title: "Software and Data Integrity Failures", vulns: [] },
        "A09:2021": { title: "Security Logging and Monitoring Failures", vulns: [] },
        "A10:2021": { title: "Server-Side Request Forgery (SSRF)", vulns: [] },
      };

      for (const v of data.vulnerabilities) {
        if (v.owasp && owaspMap[v.owasp]) {
          owaspMap[v.owasp].vulns.push(v);
        }
      }

      let text = `## 🛡️ OWASP Top 10 (2021) Compliance Report\n\n`;
      let compliant = 0;
      let violated = 0;

      for (const [key, { title, vulns }] of Object.entries(owaspMap)) {
        if (vulns.length === 0) {
          text += `✅ **${key}**: ${title} - **COMPLIANT**\n`;
          compliant++;
        } else {
          text += `❌ **${key}**: ${title} - **${vulns.length} issue(s)**\n`;
          violated++;
          for (const v of vulns) {
            text += `   - ${severityIcon(v.severity)} ${v.title}\n`;
          }
        }
      }

      text += `\n---\n`;
      text += `**Compliance Score:** ${Math.round((compliant / 10) * 100)}%\n`;
      text += `**Compliant:** ${compliant}/10\n`;
      text += `**Violated:** ${violated}/10\n`;

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` }],
      };
    }
  }
);

// ─── Tool: analyze_security_headers ───────────────────────────
server.tool(
  "analyze_security_headers",
  "Analyze HTTP security headers configuration. Checks for CSP, HSTS, X-Frame-Options, etc. Provide middleware or server configuration code.",
  {
    code: z.string().describe("Server/middleware code that sets HTTP headers"),
    framework: z.string().optional().describe("Framework: express, nextjs, fastify, etc."),
  },
  async ({ code, framework }) => {
    const headers = {
      "Content-Security-Policy": { present: false, severity: "HIGH" },
      "Strict-Transport-Security": { present: false, severity: "HIGH" },
      "X-Frame-Options": { present: false, severity: "MEDIUM" },
      "X-Content-Type-Options": { present: false, severity: "MEDIUM" },
      "X-XSS-Protection": { present: false, severity: "LOW" },
      "Referrer-Policy": { present: false, severity: "LOW" },
      "Permissions-Policy": { present: false, severity: "LOW" },
    };

    for (const header of Object.keys(headers)) {
      if (code.includes(header) || code.includes(header.toLowerCase())) {
        headers[header as keyof typeof headers].present = true;
      }
    }

    let text = `## 🔒 Security Headers Analysis\n\n`;
    if (framework) text += `**Framework:** ${framework}\n\n`;

    let score = 0;
    const total = Object.keys(headers).length;

    for (const [header, { present, severity }] of Object.entries(headers)) {
      if (present) {
        text += `✅ **${header}** - Configured\n`;
        score++;
      } else {
        text += `❌ **${header}** - Missing (${severity} severity)\n`;
      }
    }

    text += `\n---\n`;
    text += `**Score:** ${score}/${total} (${Math.round((score / total) * 100)}%)\n\n`;

    if (score < total) {
      text += `### Recommendations\n`;
      if (!headers["Content-Security-Policy"].present) {
        text += `- Add **Content-Security-Policy** to prevent XSS attacks\n`;
      }
      if (!headers["Strict-Transport-Security"].present) {
        text += `- Add **Strict-Transport-Security** to enforce HTTPS\n`;
      }
      if (!headers["X-Frame-Options"].present) {
        text += `- Add **X-Frame-Options: DENY** to prevent clickjacking\n`;
      }
    }

    return { content: [{ type: "text" as const, text }] };
  }
);

// ─── Tool: audit_dependencies ─────────────────────────────────
server.tool(
  "audit_dependencies",
  "Audit project dependencies for known vulnerabilities using Google OSV database. Provide package.json, requirements.txt, or similar.",
  {
    manifestFile: z.string().describe("Dependency manifest file content (package.json, requirements.txt, etc.)"),
    ecosystem: z.enum(["npm", "pypi", "maven", "go", "cargo", "composer"]).optional().describe("Package ecosystem"),
  },
  async ({ manifestFile, ecosystem }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    try {
      const res = await apiCall("/api/v1/scan/inline", {
        method: "POST",
        body: JSON.stringify({
          code: manifestFile,
          scanType: "sca",
          includeExplanation: true,
          includeFix: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return {
          content: [{ type: "text" as const, text: `❌ Error (${res.status}): ${err.error}` }],
        };
      }

      const data = await res.json();
      return {
        content: [{ type: "text" as const, text: formatScanResults(data, "dependencies") }],
      };
    } catch (error) {
      return {
        content: [{ type: "text" as const, text: `❌ Error: ${error instanceof Error ? error.message : "Unknown"}` }],
      };
    }
  }
);

// ─── Tool: generate_security_report ───────────────────────────
server.tool(
  "generate_security_report",
  "Generate a comprehensive security report for a codebase. Combines SAST, SCA, OWASP compliance, and security best practices.",
  {
    projectPath: z.string().describe("Path to project root directory"),
    includeTests: z.boolean().optional().describe("Include test files in scan. Default: false"),
  },
  async ({ projectPath, includeTests }) => {
    if (!effectiveApiKey()) {
      return {
        content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }],
      };
    }

    let text = `## 📊 AETHERIA Comprehensive Security Report\n\n`;
    text += `**Project:** \`${projectPath}\`\n`;
    text += `**Generated:** ${new Date().toISOString()}\n\n`;
    text += `---\n\n`;
    text += `### Report Sections\n\n`;
    text += `1. **SAST (Static Application Security Testing)** - Source code vulnerabilities\n`;
    text += `2. **SCA (Software Composition Analysis)** - Dependency vulnerabilities\n`;
    text += `3. **OWASP Top 10 Compliance** - Industry standard security checks\n`;
    text += `4. **Security Headers** - HTTP security configuration\n`;
    text += `5. **Best Practices** - Code quality and security patterns\n\n`;
    text += `---\n\n`;
    text += `To generate this report, use the following tools:\n\n`;
    text += `1. \`scan_file\` on each source file for SAST\n`;
    text += `2. \`audit_dependencies\` on package.json/requirements.txt for SCA\n`;
    text += `3. \`check_owasp_top10\` on critical files\n`;
    text += `4. \`analyze_security_headers\` on middleware/server config\n\n`;
    text += `💡 **Tip:** Use Windsurf's file reading capabilities to scan multiple files automatically.`;

    return { content: [{ type: "text" as const, text }] };
  }
);

// ─── Tool: triage_finding ─────────────────────────────────────
server.tool(
  "triage_finding",
  "Triage an external security finding (from SARIF, CVE, GHSA, bug bounty, or scanner) against a repository. " +
    "Returns a verdict: confirmed, not_actionable, or needs_review with evidence and exploitability ranking.",
  {
    title: z.string().describe("Finding title"),
    sourceType: z.enum(["sarif", "cve", "advisory", "scanner_ticket", "bug_bounty", "freeform"]).describe("Source type of the finding"),
    description: z.string().optional().describe("Finding description"),
    component: z.string().optional().describe("Affected component/path"),
    cweId: z.string().optional().describe("CWE identifier (e.g. CWE-89)"),
    cveId: z.string().optional().describe("CVE identifier if applicable"),
  },
  async ({ title, sourceType, description, component, cweId, cveId }) => {
    if (!effectiveApiKey()) {
      return { content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }] };
    }

    try {
      const res = await apiCall("/api/triage", {
        method: "POST",
        body: JSON.stringify({
          findings: [{ title, sourceType, description, component, cweId, cveId }],
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return { content: [{ type: "text" as const, text: `❌ Triage error (${res.status}): ${err.error}` }] };
      }

      const data = await res.json();
      const result = data.results?.[0];
      if (!result) return { content: [{ type: "text" as const, text: "No verdict produced." }] };

      let text = `## 🔍 Triage Verdict: ${result.verdict.toUpperCase()}\n\n`;
      text += `**Finding:** ${title}\n`;
      text += `**Confidence:** ${result.confidence}\n\n`;
      text += `### Rationale\n${result.rationale}\n\n`;
      if (result.boundaryAssessment) {
        text += `### Boundary Assessment\n`;
        text += `- Surface: ${result.boundaryAssessment.surface}\n`;
        text += `- Source trust: ${result.boundaryAssessment.sourceTrust}\n`;
        text += `- Boundary crossed: ${result.boundaryAssessment.boundaryCrossed ? "Yes" : "No"}\n\n`;
      }
      if (result.evidence) text += `### Evidence\n${result.evidence}\n\n`;
      if (result.recommendedNext) text += `### Recommended Action\n${result.recommendedNext}\n`;

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return { content: [{ type: "text" as const, text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown"}` }] };
    }
  }
);

// ─── Tool: generate_writeup ───────────────────────────────────
server.tool(
  "generate_writeup",
  "Generate a disclosure-quality vulnerability writeup for a specific finding. " +
    "Includes executive summary, vulnerability details, exploitability analysis, PoC structure, and remediation.",
  {
    vulnerabilityId: z.string().describe("ID of the vulnerability to generate writeup for"),
  },
  async ({ vulnerabilityId }) => {
    if (!effectiveApiKey()) {
      return { content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }] };
    }

    try {
      const res = await apiCall(`/api/vulnerabilities/${vulnerabilityId}/writeup`, { method: "POST" });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return { content: [{ type: "text" as const, text: `❌ Writeup error (${res.status}): ${err.error}` }] };
      }

      const data = await res.json();
      return { content: [{ type: "text" as const, text: data.writeup || "No writeup generated." }] };
    } catch (error) {
      return { content: [{ type: "text" as const, text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown"}` }] };
    }
  }
);

// ─── Tool: compare_scans ──────────────────────────────────────
server.tool(
  "compare_scans",
  "Compare two security scans using LLM-based root-cause matching. " +
    "Identifies which findings are the same root cause, which are resolved, and which are newly introduced.",
  {
    currentAnalysisId: z.string().describe("ID of the current (newer) analysis"),
    previousAnalysisId: z.string().describe("ID of the previous (older) analysis to compare against"),
  },
  async ({ currentAnalysisId, previousAnalysisId }) => {
    if (!effectiveApiKey()) {
      return { content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }] };
    }

    try {
      const res = await apiCall(`/api/analyses/${currentAnalysisId}/compare?with=${previousAnalysisId}`);

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return { content: [{ type: "text" as const, text: `❌ Comparison error (${res.status}): ${err.error}` }] };
      }

      const data = await res.json();
      let text = `## 📊 Scan Comparison Results\n\n`;
      text += `**Summary:** ${data.summary}\n\n`;
      text += `### Matches (${data.matches?.length || 0})\n`;
      for (const m of data.matches || []) {
        text += `- \`${m.prevId}\` ↔ \`${m.currId}\` (${m.confidence}): ${m.rationale}\n`;
      }
      text += `\n### Resolved (${data.resolved?.length || 0})\n`;
      text += (data.resolved || []).map((id: string) => `- ${id}`).join("\n") || "None";
      text += `\n\n### Introduced (${data.introduced?.length || 0})\n`;
      text += (data.introduced || []).map((id: string) => `- ${id}`).join("\n") || "None";

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return { content: [{ type: "text" as const, text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown"}` }] };
    }
  }
);

// ─── Tool: propose_hardening ──────────────────────────────────
server.tool(
  "propose_hardening",
  "Generate structural security hardening proposals for a completed analysis. " +
    "Returns a portfolio of improvement opportunities with options, tradeoffs, and recommendations.",
  {
    analysisId: z.string().describe("ID of the completed analysis to generate hardening proposals for"),
  },
  async ({ analysisId }) => {
    if (!effectiveApiKey()) {
      return { content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }] };
    }

    try {
      const res = await apiCall(`/api/analyses/${analysisId}/hardening`, { method: "POST" });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return { content: [{ type: "text" as const, text: `❌ Hardening error (${res.status}): ${err.error}` }] };
      }

      const data = await res.json();
      let text = `## 🔧 Security Hardening Proposals\n\n`;
      for (const opp of data.opportunities || []) {
        text += `### ${opp.opportunityId}: ${opp.title}\n`;
        text += `**Diagnosis:** ${opp.diagnosis}\n\n`;
        for (const opt of opp.options || []) {
          const rec = opp.recommended === opt.optionId ? " ⭐ RECOMMENDED" : "";
          text += `- **${opt.optionId}: ${opt.title}**${rec}\n`;
          text += `  ${opt.summary}\n`;
          text += `  Residual risk: ${opt.residualRisks}\n`;
        }
        text += "\n";
      }

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return { content: [{ type: "text" as const, text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown"}` }] };
    }
  }
);

// ─── Tool: get_threat_model ───────────────────────────────────
server.tool(
  "get_threat_model",
  "Retrieve the AI-generated threat model for a completed analysis. " +
    "Includes actors, trust boundaries, assets, and threat scenarios.",
  {
    analysisId: z.string().describe("ID of the analysis to get threat model for"),
  },
  async ({ analysisId }) => {
    if (!effectiveApiKey()) {
      return { content: [{ type: "text" as const, text: "❌ AETHERIA_API_KEY not configured." }] };
    }

    try {
      const res = await apiCall(`/api/analyses/${analysisId}/threat-model`);

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        return { content: [{ type: "text" as const, text: `❌ Threat model error (${res.status}): ${err.error}` }] };
      }

      const data = await res.json();
      let text = `## 🛡️ Threat Model\n\n`;
      text += `### Actors\n`;
      for (const actor of data.actors || []) {
        text += `- **${actor.name}**: ${actor.description}\n`;
      }
      text += `\n### Trust Boundaries\n`;
      for (const b of data.boundaries || []) {
        text += `- **${b.name}** (${b.trustLevel}): ${b.description}\n`;
      }
      text += `\n### Assets\n`;
      for (const a of data.assets || []) {
        text += `- **${a.name}** (sensitivity: ${a.sensitivity}): ${a.location}\n`;
      }
      text += `\n### Threats\n`;
      for (const t of data.threats || []) {
        text += `- **${t.id}**: ${t.description} (actor: ${t.actor}, likelihood: ${t.likelihood}, impact: ${t.impact})\n`;
      }

      return { content: [{ type: "text" as const, text }] };
    } catch (error) {
      return { content: [{ type: "text" as const, text: `❌ Connection error: ${error instanceof Error ? error.message : "Unknown"}` }] };
    }
  }
);

// ─── Start Server ─────────────────────────────────────────────
async function startStdio() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("AETHERIA Security MCP Server running on stdio");
}

/**
 * StreamableHTTP transport for remote agents (Devin, cloud IDEs, CI bots).
 * Stateful sessions; clients authenticate per-request with their own
 * `Authorization: Bearer <AETHERIA_API_KEY>` — the key is forwarded to the
 * platform, so one hosted MCP serves every company.
 */
function startHttp() {
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end("Not Found");
      return;
    }
    const bearer = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");

    // Read JSON body for POST requests
    let body: unknown;
    if (req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        res.writeHead(400).end("Invalid JSON");
        return;
      }
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let transport = sessionId ? transports.get(sessionId) : undefined;

    if (!transport) {
      if (req.method === "POST" && isInitializeRequest(body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, transport!);
          },
        });
        transport.onclose = () => {
          if (transport?.sessionId) transports.delete(transport.sessionId);
        };
        await server.connect(transport);
      } else {
        res.writeHead(400).end("Bad Request: no valid session");
        return;
      }
    }

    await requestContext.run({ apiKey: bearer || undefined }, () =>
      transport!.handleRequest(req, res, body)
    );
  });

  httpServer.listen(MCP_HTTP_PORT, () => {
    console.error(`AETHERIA Security MCP Server (StreamableHTTP) on :${MCP_HTTP_PORT}/mcp`);
  });
}

async function main() {
  if (MCP_TRANSPORT === "stdio" || MCP_TRANSPORT === "all") await startStdio();
  if (MCP_TRANSPORT === "http" || MCP_TRANSPORT === "all") startHttp();
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});

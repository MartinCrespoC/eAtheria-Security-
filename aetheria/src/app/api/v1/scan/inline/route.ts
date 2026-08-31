import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey, hasScope } from "@/lib/api-auth";
import { rateLimit, getClientIp } from "@/lib/rate-limit";
import { generateWithGemini } from "@/lib/ai";

/**
 * POST /api/v1/scan/inline
 * Real-time code scanning — send code, get vulnerabilities back immediately.
 * Designed for MCP server / IDE integration.
 *
 * Headers:
 *   Authorization: Bearer aeth_xxxxx
 *
 * Body:
 *   {
 *     "code": "string — source code to scan",
 *     "language": "typescript",       // optional, auto-detected if omitted
 *     "filePath": "src/auth.ts",      // optional, for context
 *     "scanType": "sast",             // "sast" | "sca" | "full"
 *     "includeExplanation": true,     // optional, default true
 *     "includeFix": true              // optional, default true
 *   }
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);
  const rl = rateLimit(`api:inline:${ip}`, { maxRequests: 30, windowMs: 60_000 });
  if (!rl.success) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Max 30 inline scans/minute." },
      { status: 429 }
    );
  }

  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json(
      { error: "Invalid or expired API key. Provide: Authorization: Bearer aeth_xxx" },
      { status: 401 }
    );
  }

  if (!hasScope(ctx, "analysis:create")) {
    return NextResponse.json(
      { error: "API key does not have 'analysis:create' scope." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const {
      code,
      language = "auto",
      filePath = "unknown",
      scanType = "sast",
      includeExplanation = true,
      includeFix = true,
    } = body;

    if (!code || typeof code !== "string") {
      return NextResponse.json(
        { error: "Field 'code' is required and must be a string." },
        { status: 400 }
      );
    }

    if (code.length > 100_000) {
      return NextResponse.json(
        { error: "Code exceeds 100KB limit. Split into smaller files." },
        { status: 400 }
      );
    }

    const detectedLang = language !== "auto" ? language : detectLanguage(filePath, code);

    let prompt = "";

    if (scanType === "sca" || scanType === "full") {
      prompt = buildScaPrompt(code, filePath, detectedLang, includeFix, includeExplanation);
    }

    if (scanType === "sast" || scanType === "full") {
      const sastPrompt = buildSastPrompt(code, filePath, detectedLang, includeFix, includeExplanation);
      prompt = scanType === "full" ? `${prompt}\n\nADDITIONALLY:\n${sastPrompt}` : sastPrompt;
    }

    const result = await generateWithGemini(prompt, {
      temperature: 0.1,
      maxOutputTokens: 8192,
      companyId: ctx.companyId,
    });

    const jsonMatch = result.text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return NextResponse.json({
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        tokensUsed: { input: result.inputTokens, output: result.outputTokens },
        model: result.modelUsed,
      });
    }

    const parsed = JSON.parse(jsonMatch[0]);
    const vulns = Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities : [];

    const summary = {
      total: vulns.length,
      critical: vulns.filter((v: { severity: string }) => v.severity === "CRITICAL").length,
      high: vulns.filter((v: { severity: string }) => v.severity === "HIGH").length,
      medium: vulns.filter((v: { severity: string }) => v.severity === "MEDIUM").length,
      low: vulns.filter((v: { severity: string }) => v.severity === "LOW").length,
      info: vulns.filter((v: { severity: string }) => v.severity === "INFO").length,
    };

    return NextResponse.json({
      vulnerabilities: vulns,
      summary,
      language: detectedLang,
      filePath,
      tokensUsed: { input: result.inputTokens, output: result.outputTokens },
      model: result.modelUsed,
    });
  } catch (error) {
    console.error("Inline scan error:", error);
    return NextResponse.json(
      { error: "Internal server error during scan." },
      { status: 500 }
    );
  }
}

function buildSastPrompt(
  code: string,
  filePath: string,
  language: string,
  includeFix: boolean,
  includeExplanation: boolean
): string {
  return `You are EATHERIA Security Scanner, an expert application security analyzer.
Analyze this ${language} code for ALL security vulnerabilities including:
- Injection flaws (SQL, NoSQL, Command, LDAP, XPath)
- Authentication & session management issues
- Cross-Site Scripting (XSS)
- Insecure deserialization
- Security misconfigurations
- Sensitive data exposure
- Broken access control
- Cryptographic failures
- SSRF, path traversal, race conditions
- Hardcoded secrets/credentials
- Unsafe regex (ReDoS)

File: ${filePath}
\`\`\`${language}
${code}
\`\`\`

Return ONLY valid JSON:
{
  "vulnerabilities": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "title": "short title",
      "description": ${includeExplanation ? '"detailed explanation of why this is vulnerable and its impact"' : '"brief description"'},
      "category": "Injection|XSS|Authentication|...",
      "cweId": "CWE-XX",
      "owasp": "A01:2021|...",
      "lineStart": number,
      "lineEnd": number,
      "codeSnippet": "vulnerable code fragment"${includeFix ? `,
      "fix": "corrected code snippet",
      "fixExplanation": "why this fix resolves the issue"` : ""}
    }
  ]
}

If NO vulnerabilities found, return: {"vulnerabilities":[]}
Be thorough but avoid false positives. Only report genuine security issues.`;
}

function buildScaPrompt(
  code: string,
  filePath: string,
  language: string,
  includeFix: boolean,
  includeExplanation: boolean
): string {
  return `You are EATHERIA Security Scanner analyzing a dependency/configuration file for known vulnerabilities and security issues.

File: ${filePath} (${language})
\`\`\`
${code}
\`\`\`

Check for:
- Known vulnerable dependency versions (CVEs)
- Outdated packages with security patches available
- Insecure dependency configurations
- Typosquatting risks
- Overly permissive version ranges

Return ONLY valid JSON:
{
  "vulnerabilities": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "title": "package@version — CVE/issue",
      "description": ${includeExplanation ? '"detailed explanation"' : '"brief description"'},
      "category": "Vulnerable Dependency|Outdated Package|...",
      "cweId": "CWE-XX",
      "package": "package-name",
      "currentVersion": "x.y.z",
      "patchedVersion": "a.b.c"${includeFix ? `,
      "fix": "updated dependency line",
      "fixExplanation": "explanation"` : ""}
    }
  ]
}

If NO vulnerabilities found, return: {"vulnerabilities":[]}`;
}

function detectLanguage(filePath: string, code: string): string {
  const ext = filePath.split(".").pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript",
    py: "python", rb: "ruby", java: "java", kt: "kotlin", go: "go",
    rs: "rust", cs: "csharp", cpp: "cpp", c: "c", php: "php",
    swift: "swift", dart: "dart", scala: "scala", r: "r",
    sql: "sql", sh: "bash", yml: "yaml", yaml: "yaml",
    json: "json", xml: "xml", html: "html", css: "css",
    tf: "terraform", hcl: "terraform",
    dockerfile: "dockerfile", "docker-compose": "yaml",
  };

  if (ext && langMap[ext]) return langMap[ext];

  // Detect by filename
  const name = filePath.split("/").pop()?.toLowerCase() || "";
  if (name === "dockerfile") return "dockerfile";
  if (name === "package.json" || name === "package-lock.json") return "json";
  if (name === "requirements.txt" || name === "pipfile") return "python";
  if (name === "gemfile") return "ruby";
  if (name === "pom.xml" || name === "build.gradle") return "java";
  if (name === "go.mod") return "go";
  if (name === "cargo.toml") return "rust";

  // Fallback: detect from code content
  if (code.includes("import React") || code.includes("from 'react'")) return "typescript";
  if (code.includes("def ") && code.includes("import ")) return "python";
  if (code.includes("func ") && code.includes("package ")) return "go";

  return "unknown";
}

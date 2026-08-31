import { prisma } from "@/lib/db";
import { generateWithGemini } from "@/lib/ai";
import type { KnowledgeIndex } from "@/lib/knowledge";
import { getRootCauseForCwe } from "@/lib/knowledge";

interface DastResult {
  vulnerabilities: DastVulnerability[];
  summary: {
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  };
  metadata: {
    url: string;
    statusCode: number;
    responseTime: number;
    headers: Record<string, string>;
    technologies: string[];
  };
  tokenUsage: { inputTokens: number; outputTokens: number; cost: number };
}

interface DastVulnerability {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  title: string;
  description: string;
  cweId?: string;
  owaspTop10?: string;
  evidence?: string;
  smartFix?: string;
  fixExplanation?: string;
}

// Security headers that should be present
const EXPECTED_HEADERS: { header: string; cweId: string; severity: "HIGH" | "MEDIUM" | "LOW"; title: string }[] = [
  { header: "strict-transport-security", cweId: "CWE-319", severity: "HIGH", title: "Missing HSTS Header" },
  { header: "x-content-type-options", cweId: "CWE-16", severity: "MEDIUM", title: "Missing X-Content-Type-Options" },
  { header: "x-frame-options", cweId: "CWE-1021", severity: "MEDIUM", title: "Missing X-Frame-Options (Clickjacking)" },
  { header: "content-security-policy", cweId: "CWE-693", severity: "MEDIUM", title: "Missing Content-Security-Policy" },
  { header: "x-xss-protection", cweId: "CWE-79", severity: "LOW", title: "Missing X-XSS-Protection" },
  { header: "referrer-policy", cweId: "CWE-200", severity: "LOW", title: "Missing Referrer-Policy" },
  { header: "permissions-policy", cweId: "CWE-16", severity: "LOW", title: "Missing Permissions-Policy" },
];

// Dangerous headers that should NOT be present
const DANGEROUS_HEADERS: { header: string; cweId: string; severity: "MEDIUM" | "LOW"; title: string }[] = [
  { header: "server", cweId: "CWE-200", severity: "LOW", title: "Server Version Disclosure" },
  { header: "x-powered-by", cweId: "CWE-200", severity: "LOW", title: "Technology Stack Disclosure (X-Powered-By)" },
  { header: "x-aspnet-version", cweId: "CWE-200", severity: "MEDIUM", title: "ASP.NET Version Disclosure" },
];

export async function runDastAnalysis(
  analysisId: string,
  targetUrl: string,
  companyId: string,
  knowledgeIndex?: KnowledgeIndex
): Promise<DastResult> {
  const vulns: DastVulnerability[] = [];
  let statusCode = 0;
  let responseTime = 0;
  const headers: Record<string, string> = {};
  const technologies: string[] = [];
  let dastInputTokens = 0;
  let dastOutputTokens = 0;
  let dastCost = 0;

  // Phase 1: HTTP probe
  try {
    const start = Date.now();
    const res = await fetch(targetUrl, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(15000),
      headers: { "User-Agent": "EATHERIA-DAST/1.0" },
    });
    responseTime = Date.now() - start;
    statusCode = res.status;

    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // Detect technologies from headers
    if (headers["x-powered-by"]) technologies.push(headers["x-powered-by"]);
    if (headers["server"]) technologies.push(headers["server"]);

    // Phase 2: Security header checks
    for (const check of EXPECTED_HEADERS) {
      if (!headers[check.header]) {
        vulns.push({
          severity: check.severity,
          confidence: "HIGH",
          category: "Security Headers",
          title: check.title,
          description: `The response from ${targetUrl} is missing the ${check.header} header, which helps protect against common attacks.`,
          cweId: check.cweId,
          owaspTop10: "A05:2021",
          evidence: `Header '${check.header}' not found in response`,
          smartFix: `Add the '${check.header}' header to your server responses.`,
        });
      }
    }

    for (const check of DANGEROUS_HEADERS) {
      if (headers[check.header]) {
        vulns.push({
          severity: check.severity,
          confidence: "HIGH",
          category: "Information Disclosure",
          title: check.title,
          description: `The server exposes ${check.header}: ${headers[check.header]}, revealing technology details to attackers.`,
          cweId: check.cweId,
          owaspTop10: "A05:2021",
          evidence: `${check.header}: ${headers[check.header]}`,
          smartFix: `Remove or suppress the '${check.header}' header in production.`,
        });
      }
    }

    // Phase 3: Cookie security checks
    const setCookies = res.headers.getSetCookie?.() || [];
    for (const cookie of setCookies) {
      const cookieName = cookie.split("=")[0];
      if (!cookie.toLowerCase().includes("httponly")) {
        vulns.push({
          severity: "MEDIUM",
          confidence: "HIGH",
          category: "Cookie Security",
          title: `Cookie '${cookieName}' Missing HttpOnly Flag`,
          description: "Cookies without HttpOnly can be accessed via JavaScript, enabling XSS-based session theft.",
          cweId: "CWE-1004",
          owaspTop10: "A05:2021",
          evidence: cookie,
          smartFix: `Set the HttpOnly flag on cookie '${cookieName}'.`,
        });
      }
      if (!cookie.toLowerCase().includes("secure")) {
        vulns.push({
          severity: "MEDIUM",
          confidence: "HIGH",
          category: "Cookie Security",
          title: `Cookie '${cookieName}' Missing Secure Flag`,
          description: "Cookies without the Secure flag may be transmitted over unencrypted HTTP connections.",
          cweId: "CWE-614",
          owaspTop10: "A05:2021",
          evidence: cookie,
          smartFix: `Set the Secure flag on cookie '${cookieName}'.`,
        });
      }
      if (!cookie.toLowerCase().includes("samesite")) {
        vulns.push({
          severity: "LOW",
          confidence: "MEDIUM",
          category: "Cookie Security",
          title: `Cookie '${cookieName}' Missing SameSite Attribute`,
          description: "Without SameSite, cookies may be sent in cross-site requests, enabling CSRF.",
          cweId: "CWE-352",
          owaspTop10: "A01:2021",
          evidence: cookie,
          smartFix: `Set SameSite=Lax or SameSite=Strict on cookie '${cookieName}'.`,
        });
      }
    }

    // Phase 4: HTTPS check
    if (!targetUrl.startsWith("https://")) {
      vulns.push({
        severity: "HIGH",
        confidence: "HIGH",
        category: "Transport Security",
        title: "Site Does Not Use HTTPS",
        description: "The target URL uses HTTP instead of HTTPS, exposing all traffic to interception.",
        cweId: "CWE-319",
        owaspTop10: "A02:2021",
        evidence: `URL: ${targetUrl}`,
        smartFix: "Enable HTTPS with a valid TLS certificate and redirect all HTTP to HTTPS.",
      });
    }

    // Phase 5: AI-powered analysis of response body (with BugHunter knowledge)
    const body = await res.text();
    const bodyPreview = body.substring(0, 15000);

    if (bodyPreview.length > 100) {
      const aiResult = await analyzeResponseWithAI(targetUrl, bodyPreview, headers, companyId, technologies, knowledgeIndex);
      vulns.push(...aiResult.vulns);
      dastInputTokens += aiResult.inputTokens;
      dastOutputTokens += aiResult.outputTokens;
      dastCost += aiResult.cost;
    }
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : "Unknown error";
    vulns.push({
      severity: "INFO",
      confidence: "HIGH",
      category: "Connectivity",
      title: "Target Unreachable or Timeout",
      description: `Could not connect to ${targetUrl}: ${errMsg}`,
    });
  }

  // Store vulnerabilities in DB with DAST metadata
  for (const vuln of vulns) {
    const rootCause = knowledgeIndex && vuln.cweId
      ? getRootCauseForCwe(knowledgeIndex, vuln.cweId)
      : null;

    await prisma.vulnerability.create({
      data: {
        severity: vuln.severity,
        confidence: vuln.confidence,
        category: vuln.category,
        title: vuln.title,
        description: vuln.description,
        cweId: vuln.cweId,
        owaspTop10: vuln.owaspTop10,
        codeSnippet: vuln.evidence,
        smartFix: vuln.smartFix,
        fixExplanation: vuln.fixExplanation,
        detectionMethod: "DAST",
        rootCause,
        analysisId,
      },
    });
  }

  const summary = {
    totalIssues: vulns.length,
    criticalCount: vulns.filter((v) => v.severity === "CRITICAL").length,
    highCount: vulns.filter((v) => v.severity === "HIGH").length,
    mediumCount: vulns.filter((v) => v.severity === "MEDIUM").length,
    lowCount: vulns.filter((v) => v.severity === "LOW").length,
    infoCount: vulns.filter((v) => v.severity === "INFO").length,
  };

  await prisma.analysis.update({
    where: { id: analysisId },
    data: {
      totalIssues: { increment: summary.totalIssues },
      criticalCount: { increment: summary.criticalCount },
      highCount: { increment: summary.highCount },
      mediumCount: { increment: summary.mediumCount },
      lowCount: { increment: summary.lowCount },
      infoCount: { increment: summary.infoCount },
    },
  });

  return {
    vulnerabilities: vulns,
    summary,
    metadata: { url: targetUrl, statusCode, responseTime, headers, technologies },
    tokenUsage: { inputTokens: dastInputTokens, outputTokens: dastOutputTokens, cost: dastCost },
  };
}

async function analyzeResponseWithAI(
  url: string,
  body: string,
  headers: Record<string, string>,
  companyId: string,
  technologies: string[],
  knowledgeIndex?: KnowledgeIndex
): Promise<{ vulns: DastVulnerability[]; inputTokens: number; outputTokens: number; cost: number }> {
  // Build technology-specific knowledge context from BugHunter
  let knowledgeContext = "";
  if (knowledgeIndex) {
    const techSkills: string[] = [];
    const techLower = technologies.map((t) => t.toLowerCase());
    for (const skill of knowledgeIndex.allSkills) {
      const fws = skill.frameworks as string[];
      const signals = skill.attackSignals as { type: string; pattern: string }[] | null;
      // Match by detected technology
      if (fws.some((f) => techLower.some((t) => t.includes(f)))) {
        const signals_text = signals?.slice(0, 3).map((s) => s.pattern).join("; ") || "";
        techSkills.push(`[${skill.name}] ${signals_text}`);
      }
    }
    if (techSkills.length > 0) {
      knowledgeContext = `\n=== BUGUNTER ATTACK SURFACE (detected technologies) ===\n${techSkills.slice(0, 5).join("\n")}\n`;
    }
  }

  const prompt = `You are an expert web application security scanner performing DAST (Dynamic Application Security Testing).
Analyze this HTTP response for security vulnerabilities.

Target URL: ${url}
Detected Technologies: ${technologies.join(", ") || "unknown"}
Response Headers: ${JSON.stringify(headers, null, 2)}
${knowledgeContext}
Response Body (first 15KB):
${body}

Look for:
- Sensitive data exposure (emails, API keys, tokens, internal paths)
- Error messages revealing stack traces or internal info
- Insecure form actions (HTTP POST to HTTP URLs)
- Mixed content (HTTPS page loading HTTP resources)
- DOM-based XSS sinks (innerHTML, eval, document.write patterns)
- Insecure JavaScript patterns
- Missing CSRF tokens in forms
- Open redirect patterns
- Version numbers or debug info

Respond ONLY with a JSON array of vulnerability objects. Each object:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "HIGH|MEDIUM|LOW",
  "category": "string",
  "title": "string",
  "description": "string",
  "cweId": "CWE-XX",
  "owaspTop10": "AXX:2021",
  "evidence": "relevant snippet",
  "smartFix": "how to fix",
  "fixExplanation": "why this fix works"
}

If no vulnerabilities found, return [].`;

  try {
    const result = await generateWithGemini(prompt, {
      companyId,
      systemInstruction: "You are a DAST security scanner. Return valid JSON only.",
      temperature: 0.1,
    });

    const cleaned = result.text
      .replace(/```json\n?/g, "")
      .replace(/```\n?/g, "")
      .trim();

    const parsed = JSON.parse(cleaned);
    const vulns = Array.isArray(parsed) ? parsed : [];
    return { vulns, inputTokens: result?.inputTokens ?? 0, outputTokens: result?.outputTokens ?? 0, cost: result?.cost ?? 0 };
  } catch {
    console.error("Failed to parse DAST AI results");
    return { vulns: [], inputTokens: 0, outputTokens: 0, cost: 0 };
  }
}

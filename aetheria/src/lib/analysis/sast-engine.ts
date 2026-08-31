/**
 * SAST Engine — Per-file, token-optimized, knowledge-enriched
 * Replaces the old single-prompt approach (30k char cap) with:
 * - File risk scoring & prioritization
 * - Budget-aware batching (high-risk individual, low-risk grouped)
 * - BugHunter knowledge injection from DB
 * - Concurrency-limited parallel AI calls
 */

import { prisma } from "@/lib/db";
import { generateWithGemini } from "@/lib/ai";
import { buildSystemInstruction } from "@/lib/analysis/scan-prompt-builder";
import type { ScanLevel } from "@/lib/analysis/scan-knowledge";
import { CWE_KNOWLEDGE_BASE } from "@/lib/analysis/scan-knowledge";
import type { KnowledgeIndex } from "@/lib/knowledge";
import { buildKnowledgeContext, getRootCauseForCwe } from "@/lib/knowledge";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScoredFile {
  path: string;
  content: string;
  language: string;
  riskScore: number;
}

interface SastVulnerability {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  category: string;
  title: string;
  description: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  codeSnippet?: string;
  cweId?: string;
  owaspTop10?: string;
  smartFix?: string;
  fixExplanation?: string;
}

export interface SastResult {
  vulnerabilities: SastVulnerability[];
  summary: {
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  };
  filesAnalyzed: number;
  filesSkipped: number;
  tokenUsage: { inputTokens: number; outputTokens: number; cost: number };
}

// ─── Risk Scoring ────────────────────────────────────────────────────────────

const HIGH_RISK_PATTERNS: [RegExp, number][] = [
  [/child_process|exec\(|execSync|spawn\(/, 30],
  [/eval\(|new Function\(|vm\.run/, 30],
  [/\.query\(|\.raw\(|\.execute\(|rawQuery/, 25],
  [/dangerouslySetInnerHTML|innerHTML|v-html/, 25],
  [/deserialize|unserialize|pickle\.loads|ObjectInputStream/, 25],
  [/passport|jwt|bcrypt|auth|login|session|token/, 20],
  [/multer|upload|formidable|multipart/, 20],
  [/crypto\.|createCipher|createHash|pbkdf2/, 15],
  [/process\.env|SECRET|API_KEY|PASSWORD|PRIVATE_KEY/, 15],
  [/redirect|location\.href|window\.location/, 15],
  [/fetch\(|axios|request\(|http\.get|https\.get/, 10],
  [/\.send\(|res\.json|res\.render|res\.write/, 10],
  [/require\(|import .+ from/, 5],
];

/**
 * Score a file's risk level based on security-relevant patterns.
 * Returns 0-100.
 */
export function scoreFileRisk(content: string, filePath: string): number {
  let score = 0;

  for (const [pattern, weight] of HIGH_RISK_PATTERNS) {
    if (pattern.test(content)) {
      score += weight;
    }
  }

  // Path-based bonuses
  const lowerPath = filePath.toLowerCase();
  if (/auth|login|session|middleware|guard/.test(lowerPath)) score += 15;
  if (/api|route|controller|handler|endpoint/.test(lowerPath)) score += 10;
  if (/upload|file|download|export/.test(lowerPath)) score += 10;
  if (/admin|config|setting/.test(lowerPath)) score += 10;
  if (/payment|billing|stripe|checkout/.test(lowerPath)) score += 15;
  if (/test|spec|mock|fixture|__test/.test(lowerPath)) score -= 30;
  if (/\.min\.js|bundle|chunk|vendor/.test(lowerPath)) score -= 40;

  return Math.max(0, Math.min(100, score));
}

// ─── Tolerant JSON Parser ────────────────────────────────────────────────────

function parseAiJson<T>(text: string | null | undefined): T | null {
  if (!text) return null;
  const cleaned = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    // Try extracting array
    const arrStart = cleaned.indexOf("[");
    const arrEnd = cleaned.lastIndexOf("]");
    if (arrStart !== -1 && arrEnd > arrStart) {
      try {
        return JSON.parse(cleaned.slice(arrStart, arrEnd + 1)) as T;
      } catch { /* fall through */ }
    }
    // Try extracting object
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start !== -1 && end > start) {
      try {
        return JSON.parse(cleaned.slice(start, end + 1)) as T;
      } catch { /* fall through */ }
    }
    return null;
  }
}

// ─── Prompt Building ─────────────────────────────────────────────────────────

function buildFilePrompt(
  files: { path: string; content: string; language: string }[],
  scanLevel: ScanLevel,
  knowledgeContext: string,
  securePatterns: string[],
  cweGuidance: string
): string {
  const isSingle = files.length === 1;
  const header = isSingle
    ? `Analyze this ${files[0].language} file for security vulnerabilities.\nFile: ${files[0].path}`
    : `Analyze these ${files.length} files for security vulnerabilities.`;

  const codeSections = files
    .map((f) => `--- ${f.path} ---\n\`\`\`${f.language}\n${f.content.substring(0, 12000)}\n\`\`\``)
    .join("\n\n");

  return `${header}

=== SECURE PATTERNS (DO NOT FLAG) ===
${securePatterns.map((p) => `✓ ${p}`).join("\n")}
${cweGuidance ? `\n=== CWE FALSE-POSITIVE GUIDANCE (DO NOT FLAG) ===\n${cweGuidance}\n` : ""}${knowledgeContext ? `\n${knowledgeContext}\n` : ""}
=== RULES ===
1. ONLY report TRUE vulnerabilities with clear evidence.
2. ORM queries (Prisma, Mongoose, Hibernate) are NOT SQL injection.
3. bcrypt/argon2/scrypt are SECURE — not "weak crypto".
4. Framework auth decorators are NOT "missing auth".
5. Prefer precision over recall. No speculative findings.
6. Include smartFix code for every finding.
${scanLevel === "DEEP" ? "7. Trace data flow from user input (source) to dangerous function (sink).\n8. Report the full path: source → transform → sink." : scanLevel === "LIGHTWEIGHT" ? "7. Track taint within each file." : "7. Focus on obvious patterns: hardcoded secrets, eval with user input, raw SQL concatenation."}

=== OUTPUT ===
Respond ONLY with a JSON array. Each object:
{"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","confidence":"HIGH|MEDIUM|LOW","category":"...","title":"...","description":"...","filePath":"...","lineStart":0,"lineEnd":0,"codeSnippet":"...","cweId":"CWE-XXX","owaspTop10":"A0X:2021","smartFix":"...","fixExplanation":"..."}

If no real vulnerabilities, respond with [].

${codeSections}`;
}

// ─── Secure Patterns (loaded from DB FalsePositivePattern in production) ─────

const DEFAULT_SECURE_PATTERNS: Record<string, string[]> = {
  javascript: [
    "bcrypt/argon2/scrypt for password hashing (SECURE)",
    "Prisma/Mongoose/Knex ORM queries (parameterized)",
    "Express helmet/cors/rate-limit middleware (security controls)",
    "Zod/class-validator validation (prevents CWE-20)",
    "crypto.createHash('sha256')/randomBytes (secure crypto)",
    "DOMPurify/sanitize-html usage (XSS fix)",
    "Secrets loaded from env vars (process.env.X, requireEnv('X'), configService.get('X')) are the CORRECT CWE-798 fix — only flag LITERAL secret values in source",
    "nanoid customAlphabet('abc123...') defines an ID character set, NOT a secret (not CWE-798)",
    "@Throttle/@Throttler/express-rate-limit decorators ARE the CWE-307 (brute-force) fix, not a vulnerability",
    "SSRF protection that dns.lookup-resolves a host and rejects internal/private/link-local IPs before connecting IS the CWE-918 fix, not a vulnerability",
    "Empty-string form initial values (field: '') and UI placeholder text are NOT hardcoded tokens",
  ],
  typescript: [
    "bcrypt/argon2/scrypt for password hashing (SECURE)",
    "Prisma ORM operations (parameterized queries)",
    "NestJS decorators (@Injectable, @Controller, @Guard, @Pipe)",
    "Zod schema validation (runtime type safety)",
    "crypto module with SHA-256+, AES-256-GCM, randomBytes",
    "Secrets loaded from env vars (process.env.X, requireEnv('X'), ConfigService.get('X')) are the CORRECT CWE-798 fix — only flag LITERAL secret values in source",
    "nanoid customAlphabet('abc123...') defines an ID character set, NOT a secret (not CWE-798)",
    "@Throttle/@Throttler rate-limit decorators ARE the CWE-307 (brute-force) fix, not a vulnerability",
    "SSRF protection that dns.lookup-resolves a host and rejects internal/private/link-local IPs before connecting IS the CWE-918 fix, not a vulnerability",
    "Empty-string form initial values (field: '') and UI placeholder text are NOT hardcoded tokens",
    "Timing-safe token comparison (timingSafeEqual / tokenMatches) is a SECURE pattern",
  ],
  python: [
    "Django ORM queries (parameterized by default)",
    "subprocess.run with list arguments (no shell injection)",
    "secrets module usage (cryptographically secure)",
    "hashlib.sha256+ / bcrypt / argon2 (secure hashing)",
    "Secrets loaded from os.environ / os.getenv('X') are the CORRECT CWE-798 fix — only flag LITERAL secret values",
  ],
  java: [
    "PreparedStatement with setXxx() (parameterized SQL)",
    "Spring @Autowired/@Inject (dependency injection)",
    "Spring Security @PreAuthorize (authorization)",
    "JPA/Hibernate criteria queries (parameterized)",
    "Secrets loaded from System.getenv('X') / System.getProperty('X') are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  kotlin: [
    "Spring Boot @RestController/@Service annotations (framework)",
    "JPA @Entity/@Query with named parameters (parameterized)",
    "Secrets loaded from System.getenv('X') are the CORRECT CWE-798 fix — only flag LITERAL values",
    "MessageDigest SHA-256 / Cipher AES-GCM (secure crypto)",
  ],
  scala: [
    "Slick/doobie parameterized queries",
    "Play Framework Action builders (built-in CSRF)",
    "Either/Try/ZIO effect types (error handling)",
    "Secrets loaded from sys.env('X') / System.getenv are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  ruby: [
    "ActiveRecord/Sequel ORM queries (parameterized)",
    "Rails strong parameters (require/permit) (mass-assignment protection)",
    "bcrypt has_secure_password (secure password hashing)",
    "ERB html_escape / Rails auto-escaping (XSS fix)",
    "Secrets loaded from ENV['X'] / ENV.fetch('X') are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  go: [
    "database/sql with $1/? placeholders (parameterized)",
    "html/template auto-escaping (XSS fix)",
    "golang.org/x/crypto/bcrypt (secure password hashing)",
    "context.Context usage (standard cancellation)",
    "Secrets loaded from os.Getenv('X') / os.LookupEnv('X') are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  rust: [
    "sqlx/diesel parameterized queries (bind parameters)",
    "Result<T,E> / ? operator (error handling, not a flaw)",
    "ring/rustls crypto (secure cryptography)",
    "Secrets loaded from std::env::var('X') / env!('X') are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  swift: [
    "SwiftUI @State/@Binding property wrappers (UI framework)",
    "Keychain Services (secure credential storage)",
    "CryptoKit SHA256/AES.GCM (secure crypto)",
    "Secrets loaded from ProcessInfo.processInfo.environment are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  csharp: [
    "Entity Framework / Dapper parameterized queries",
    "ASP.NET [Authorize] / [ValidateAntiForgeryToken] (auth + CSRF)",
    "BCrypt.Net / Rfc2898DeriveBytes (secure hashing)",
    "Secrets loaded from Environment.GetEnvironmentVariable / IConfiguration are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
  php: [
    "PDO/MySQLi prepared statements with bound parameters (parameterized)",
    "Laravel Eloquent ORM (parameterized)",
    "password_hash()/password_verify() (secure hashing)",
    "htmlspecialchars()/e() Blade escaping (XSS fix)",
    "Secrets loaded from getenv('X') / env('X') / $_ENV are the CORRECT CWE-798 fix — only flag LITERAL values",
  ],
};

// ─── CWE → FP "DO NOT FLAG" guidance (FP Knowledge System) ─────────────────────
// Synthesized from the CweKnowledge table (MITRE CWE + Semgrep precision data)
// merged with the curated scan-knowledge false-positive scenarios. Injected into
// the SAST prompt so the AI avoids GENERATING false positives in the first place
// (automatic, transparent FP prevention). Language-agnostic and token-bounded.

let cweGuidanceCache: { value: string; at: number } | null = null;
const CWE_GUIDANCE_TTL_MS = 10 * 60 * 1000; // 10 min
const CWE_GUIDANCE_MAX_LINES = 15;

/** Case-insensitive dedupe preserving order. */
function dedupeCi(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    const s = v.trim();
    const key = s.toLowerCase();
    if (!s || seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

/**
 * Reject raw Semgrep AST pattern fragments (e.g. `$FUNC(...)`, `<%= ... %>`,
 * `link_to "..."`) that are stored as ingested commonFalsePositives. They carry
 * metavariables / ellipsis / ERB tags and would pollute the AI prompt with noise.
 * Curated human-readable guidance (e.g. "($1, ?, :param)") passes untouched.
 */
function isGuidanceSafe(item: string): boolean {
  if (/\$[A-Z_]/.test(item)) return false; // $FUNC, $CALL, $HTTPONLY metavariables
  if (item.includes("...")) return false; // Semgrep ellipsis operator
  if (/<[%=]|<\.\.\./.test(item)) return false; // ERB <%= %> or <...> wildcards
  return true;
}

async function loadCweDoNotFlagGuidance(): Promise<string> {
  if (cweGuidanceCache && Date.now() - cweGuidanceCache.at < CWE_GUIDANCE_TTL_MS) {
    return cweGuidanceCache.value;
  }
  let value = "";
  try {
    const lines: string[] = [];
    const usedCwe = new Set<string>();
    const buildLine = (cweId: string, name: string | undefined, items: string[]) => {
      const label = name && name !== cweId ? `${cweId} (${name})` : cweId;
      return `✓ ${label}: do NOT flag ${items.slice(0, 4).join("; ")}`;
    };

    // 1) Curated top CWEs (high-quality, language-agnostic FP scenarios), enriched
    //    with any ingested (Semgrep) commonFalsePositives from the CweKnowledge table.
    const dbRows = await prisma.cweKnowledge.findMany({
      where: { isActive: true, cweId: { in: CWE_KNOWLEDGE_BASE.map((c) => c.cweId) } },
    });
    const dbByCwe = new Map(dbRows.map((r) => [r.cweId, r]));
    for (const c of CWE_KNOWLEDGE_BASE) {
      const ingested = (((dbByCwe.get(c.cweId)?.commonFalsePositives as unknown) as string[] | null) ?? []).filter(
        isGuidanceSafe
      );
      const items = dedupeCi([...c.commonFalsePositives, ...ingested]);
      if (items.length === 0) continue;
      lines.push(buildLine(c.cweId, c.category, items));
      usedCwe.add(c.cweId);
      if (lines.length >= CWE_GUIDANCE_MAX_LINES) break;
    }

    // 2) Supplement: other ingested CWEs (e.g. Semgrep) that carry concrete
    //    safe-pattern false positives, ranked CWEs first.
    if (lines.length < CWE_GUIDANCE_MAX_LINES) {
      const extra = await prisma.cweKnowledge.findMany({
        where: { isActive: true, cweId: { notIn: [...usedCwe] } },
        orderBy: [{ mitreTop25Rank: "asc" }, { cweId: "asc" }],
        take: 80,
      });
      for (const row of extra) {
        const items = dedupeCi((((row.commonFalsePositives as unknown) as string[] | null) ?? []).filter(isGuidanceSafe));
        if (items.length === 0) continue;
        lines.push(buildLine(row.cweId, row.name, items));
        if (lines.length >= CWE_GUIDANCE_MAX_LINES) break;
      }
    }

    value = lines.join("\n");
  } catch (err) {
    console.error("Failed to load CWE DO-NOT-FLAG guidance:", err);
    value = "";
  }
  cweGuidanceCache = { value, at: Date.now() };
  return value;
}

// ─── Main Engine ─────────────────────────────────────────────────────────────

/**
 * Run per-file SAST analysis with knowledge enrichment.
 */
export async function runSastAnalysis(
  analysisId: string,
  files: ScoredFile[],
  language: string,
  companyId: string,
  scanLevel: ScanLevel = "STATIC",
  knowledgeIndex?: KnowledgeIndex
): Promise<SastResult> {
  // Load config from SystemConfig (budget caps)
  const [maxFilesConfig, maxBatchConfig] = await Promise.all([
    prisma.systemConfig.findUnique({ where: { key: "sast_max_files" } }),
    prisma.systemConfig.findUnique({ where: { key: "sast_max_batch_size" } }),
  ]);

  const maxFiles = parseInt(String(maxFilesConfig?.value ?? "40"), 10);
  const maxBatchSize = parseInt(String(maxBatchConfig?.value ?? "4"), 10);
  const HIGH_RISK_THRESHOLD = 40;
  const CONCURRENCY_LIMIT = 3;

  // Sort by risk (highest first) and apply budget
  const sorted = [...files].sort((a, b) => b.riskScore - a.riskScore);
  const toAnalyze = sorted.slice(0, maxFiles);
  const skipped = files.length - toAnalyze.length;

  // Build knowledge context
  const lang = language.toLowerCase();
  const knowledgeContext = knowledgeIndex
    ? buildKnowledgeContext(knowledgeIndex, [lang], undefined, 2500)
    : "";

  // Get secure patterns (prefer DB, fallback to defaults)
  const securePatterns = DEFAULT_SECURE_PATTERNS[lang] || DEFAULT_SECURE_PATTERNS["javascript"];

  // CWE → FP "DO NOT FLAG" guidance (cached, language-agnostic, token-bounded).
  const cweGuidance = await loadCweDoNotFlagGuidance();

  // Separate high-risk (individual) and low-risk (batched)
  const highRisk = toAnalyze.filter((f) => f.riskScore >= HIGH_RISK_THRESHOLD);
  const lowRisk = toAnalyze.filter((f) => f.riskScore < HIGH_RISK_THRESHOLD);

  // Build prompt groups
  const promptGroups: ScoredFile[][] = [];

  // High-risk files get individual prompts
  for (const file of highRisk) {
    promptGroups.push([file]);
  }

  // Low-risk files batched
  for (let i = 0; i < lowRisk.length; i += maxBatchSize) {
    promptGroups.push(lowRisk.slice(i, i + maxBatchSize));
  }

  const systemInstruction = buildSystemInstruction(scanLevel);
  const allVulns: SastVulnerability[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalCost = 0;

  // Process with concurrency limit
  const results: PromiseSettledResult<{ vulns: SastVulnerability[]; inputTokens: number; outputTokens: number; cost: number }>[] = [];
  for (let i = 0; i < promptGroups.length; i += CONCURRENCY_LIMIT) {
    const batch = promptGroups.slice(i, i + CONCURRENCY_LIMIT);
    const batchResults = await Promise.allSettled(
      batch.map((group) => analyzeFileGroup(group, scanLevel, knowledgeContext, securePatterns, cweGuidance, companyId, systemInstruction))
    );
    results.push(...batchResults);
  }

  // Collect results and accumulate tokens
  for (const result of results) {
    if (result.status === "fulfilled") {
      allVulns.push(...result.value.vulns);
      totalInputTokens += result.value.inputTokens;
      totalOutputTokens += result.value.outputTokens;
      totalCost += result.value.cost;
    } else {
      console.error("SAST batch failed:", result.reason);
    }
  }

  // Store vulnerabilities in DB with knowledge enrichment
  for (const vuln of allVulns) {
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
        filePath: vuln.filePath,
        lineStart: vuln.lineStart,
        lineEnd: vuln.lineEnd,
        codeSnippet: vuln.codeSnippet,
        cweId: vuln.cweId,
        owaspTop10: vuln.owaspTop10,
        smartFix: vuln.smartFix,
        fixExplanation: vuln.fixExplanation,
        detectionMethod: "AI",
        rootCause,
        analysisId,
      },
    });
  }

  const summary = {
    totalIssues: allVulns.length,
    criticalCount: allVulns.filter((v) => v.severity === "CRITICAL").length,
    highCount: allVulns.filter((v) => v.severity === "HIGH").length,
    mediumCount: allVulns.filter((v) => v.severity === "MEDIUM").length,
    lowCount: allVulns.filter((v) => v.severity === "LOW").length,
    infoCount: allVulns.filter((v) => v.severity === "INFO").length,
  };

  return { vulnerabilities: allVulns, summary, filesAnalyzed: toAnalyze.length, filesSkipped: skipped, tokenUsage: { inputTokens: totalInputTokens, outputTokens: totalOutputTokens, cost: totalCost } };
}

/**
 * Analyze a group of files (1 for high-risk, 3-5 for low-risk batch).
 */
async function analyzeFileGroup(
  files: ScoredFile[],
  scanLevel: ScanLevel,
  knowledgeContext: string,
  securePatterns: string[],
  cweGuidance: string,
  companyId: string,
  systemInstruction: string
): Promise<{ vulns: SastVulnerability[]; inputTokens: number; outputTokens: number; cost: number }> {
  const prompt = buildFilePrompt(files, scanLevel, knowledgeContext, securePatterns, cweGuidance);

  const result = await generateWithGemini(prompt, {
    companyId,
    systemInstruction,
    temperature: 0.1,
    maxOutputTokens: 4000,
  });

  const parsed = parseAiJson<SastVulnerability[]>(result?.text);
  if (!parsed || !Array.isArray(parsed)) {
    return { vulns: [], inputTokens: result?.inputTokens ?? 0, outputTokens: result?.outputTokens ?? 0, cost: result?.cost ?? 0 };
  }

  // Validate and normalize
  const vulns = parsed.filter((v) => v.title && v.severity).map((v) => ({
    ...v,
    filePath: v.filePath || files[0]?.path,
    severity: (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(v.severity) ? v.severity : "MEDIUM") as SastVulnerability["severity"],
    confidence: (["HIGH", "MEDIUM", "LOW"].includes(v.confidence) ? v.confidence : "MEDIUM") as SastVulnerability["confidence"],
  }));

  return { vulns, inputTokens: result?.inputTokens ?? 0, outputTokens: result?.outputTokens ?? 0, cost: result?.cost ?? 0 };
}

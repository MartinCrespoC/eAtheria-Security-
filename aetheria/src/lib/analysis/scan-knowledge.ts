/**
 * Security Scan Knowledge Base
 * Encodes scanning methodology knowledge from industry best practices:
 * - Static Check (L1): File-level pattern matching, known CWE signatures
 * - Lightweight Scan (L2): Change-set review, working-tree diff analysis
 * - Deep Scan (L3): Data-flow analysis, cross-file taint tracking, commit-range review
 *
 * This knowledge is used by the False Positive Detector to:
 * 1. Classify findings by scan depth
 * 2. Apply context-aware FP filtering
 * 3. Provide remediation confidence scores
 */

export type ScanLevel = "STATIC" | "LIGHTWEIGHT" | "DEEP";

export interface ScanLevelConfig {
  level: ScanLevel;
  name: string;
  description: string;
  /** Maximum file size (bytes) to analyze */
  maxFileSize: number;
  /** Whether to perform cross-file data flow analysis */
  dataFlowAnalysis: boolean;
  /** Whether to track taint propagation across function boundaries */
  taintTracking: boolean;
  /** Whether to analyze commit history for context */
  commitRangeAnalysis: boolean;
  /** FP confidence threshold (0-100) — findings below this are auto-dismissed */
  fpConfidenceThreshold: number;
  /** CWE categories that require deeper analysis before confirming */
  requiresDeepValidation: string[];
}

export const SCAN_LEVELS: Record<ScanLevel, ScanLevelConfig> = {
  STATIC: {
    level: "STATIC",
    name: "Static Check",
    description:
      "File-level pattern matching against known CWE signatures. Fast but higher false-positive rate. " +
      "Checks: hardcoded secrets, insecure crypto, SQL injection patterns, XSS sinks, path traversal.",
    maxFileSize: 1_000_000, // 1MB
    dataFlowAnalysis: false,
    taintTracking: false,
    commitRangeAnalysis: false,
    fpConfidenceThreshold: 70,
    requiresDeepValidation: [
      "CWE-89", // SQL Injection — needs context to confirm parameterization
      "CWE-79", // XSS — needs to verify sanitization upstream
      "CWE-78", // OS Command Injection — needs to verify input source
      "CWE-94", // Code Injection — needs to verify eval context
      "CWE-502", // Deserialization — needs to verify data source trust
    ],
  },
  LIGHTWEIGHT: {
    level: "LIGHTWEIGHT",
    name: "Lightweight Scan (L2)",
    description:
      "Single-pass review of working-tree changes (diff-based). Analyzes modified files with surrounding context. " +
      "Lower FP rate than static check due to change-set focus. Detects: new vulnerabilities introduced in current changes, " +
      "security regressions, missing validation on new endpoints.",
    maxFileSize: 500_000, // 500KB
    dataFlowAnalysis: true,
    taintTracking: false,
    commitRangeAnalysis: false,
    fpConfidenceThreshold: 80,
    requiresDeepValidation: [
      "CWE-89",
      "CWE-79",
      "CWE-78",
    ],
  },
  DEEP: {
    level: "DEEP",
    name: "Deep Scan (L3)",
    description:
      "Full data-flow analysis across committed changes with taint tracking. Traces user input from source to sink " +
      "across file boundaries. Analyzes commit ranges for security regressions. Lowest FP rate. " +
      "Detects: multi-step injection chains, authorization bypass via indirect references, " +
      "business logic flaws, race conditions in concurrent code paths.",
    maxFileSize: 2_000_000, // 2MB
    dataFlowAnalysis: true,
    taintTracking: true,
    commitRangeAnalysis: true,
    fpConfidenceThreshold: 90,
    requiresDeepValidation: [], // Deep scan validates everything inline
  },
};

/**
 * CWE Severity Classification Knowledge
 * Maps CWE categories to their typical true-positive rates and validation requirements
 */
export interface CweKnowledge {
  cweId: string;
  category: string;
  /** How often this CWE is a true positive in real codebases (0-100) */
  truePositiveRate: number;
  /** Common false positive scenarios for this CWE */
  commonFalsePositives: string[];
  /** Required evidence to confirm as true positive */
  confirmationEvidence: string[];
  /** OWASP Top 10 2021 mapping */
  owaspTop10?: string;
  /** MITRE Top 25 rank (if applicable) */
  mitreTop25Rank?: number;
}

export const CWE_KNOWLEDGE_BASE: CweKnowledge[] = [
  {
    cweId: "CWE-89",
    category: "SQL Injection",
    truePositiveRate: 45,
    commonFalsePositives: [
      "ORM-generated queries (Prisma, TypeORM, Hibernate, SQLAlchemy)",
      "Parameterized queries with placeholders ($1, ?, :param)",
      "Stored procedure calls with typed parameters",
      "Query builders with automatic escaping (Knex, Slick)",
      "Static SQL with no user input",
    ],
    confirmationEvidence: [
      "User input flows into SQL string concatenation",
      "No parameterization or ORM abstraction in the query path",
      "Dynamic table/column names from user input",
    ],
    owaspTop10: "A03:2021",
    mitreTop25Rank: 3,
  },
  {
    cweId: "CWE-79",
    category: "Cross-Site Scripting (XSS)",
    truePositiveRate: 40,
    commonFalsePositives: [
      "React/Vue/Angular template rendering (auto-escaped)",
      "DOMPurify or sanitize-html applied before innerHTML",
      "Server-rendered with framework escaping (Next.js, Django templates)",
      "Content-Security-Policy headers configured",
      "Static content with no user input",
    ],
    confirmationEvidence: [
      "User input rendered via innerHTML/dangerouslySetInnerHTML without sanitization",
      "No CSP headers and no output encoding",
      "Dynamic script/style injection from user data",
    ],
    owaspTop10: "A03:2021",
    mitreTop25Rank: 4,
  },
  {
    cweId: "CWE-327",
    category: "Use of Broken Cryptographic Algorithm",
    truePositiveRate: 30,
    commonFalsePositives: [
      "bcrypt/argon2/scrypt for password hashing (these are SECURE)",
      "SHA-256/SHA-3 for integrity checks (not for passwords)",
      "AES-256-GCM for encryption",
      "HMAC-SHA256 for message authentication",
      "TLS 1.3 configuration",
    ],
    confirmationEvidence: [
      "MD5 or SHA-1 used for password storage",
      "DES or RC4 for encryption",
      "ECB mode without authentication",
      "Custom/homegrown cryptographic algorithms",
    ],
    owaspTop10: "A02:2021",
    mitreTop25Rank: 12,
  },
  {
    cweId: "CWE-78",
    category: "OS Command Injection",
    truePositiveRate: 55,
    commonFalsePositives: [
      "execFile/execFileSync with array arguments (no shell)",
      "child_process.spawn with array args",
      "subprocess.run with list arguments (Python)",
      "Static commands with no user input",
      "Commands with hardcoded paths",
    ],
    confirmationEvidence: [
      "User input concatenated into shell command string",
      "exec() with template literals containing user data",
      "shell: true with user-controlled arguments",
    ],
    owaspTop10: "A03:2021",
    mitreTop25Rank: 5,
  },
  {
    cweId: "CWE-22",
    category: "Path Traversal",
    truePositiveRate: 50,
    commonFalsePositives: [
      "path.join with __dirname and static segments",
      "path.resolve with validated/whitelisted filenames",
      "Framework static file serving (Express.static, Next.js public/)",
      "File reads from configuration-defined paths",
    ],
    confirmationEvidence: [
      "User input in file path without sanitization",
      "No path.normalize + startsWith check",
      "../ sequences possible from user input",
    ],
    owaspTop10: "A01:2021",
    mitreTop25Rank: 8,
  },
  {
    cweId: "CWE-502",
    category: "Deserialization of Untrusted Data",
    truePositiveRate: 35,
    commonFalsePositives: [
      "JSON.parse of API responses (JSON is safe)",
      "Pickle with signed/verified data",
      "Protocol Buffers / Avro with schema validation",
      "Framework session deserialization (Express, Django)",
    ],
    confirmationEvidence: [
      "Java ObjectInputStream on user-controlled data",
      "PHP unserialize() on user input",
      "Python pickle.loads on network data",
      "YAML.load (not safe_load) on user input",
    ],
    owaspTop10: "A08:2021",
    mitreTop25Rank: 10,
  },
  {
    cweId: "CWE-862",
    category: "Missing Authorization",
    truePositiveRate: 60,
    commonFalsePositives: [
      "Public endpoints intentionally without auth (health checks, login)",
      "Framework-level auth middleware applied globally",
      "Route guards/decorators present (@UseGuards, @Authorize)",
      "API gateway handles authorization externally",
    ],
    confirmationEvidence: [
      "Data access without ownership verification",
      "Admin operations accessible without role check",
      "IDOR: direct object reference without authorization",
    ],
    owaspTop10: "A01:2021",
    mitreTop25Rank: 2,
  },
  {
    cweId: "CWE-798",
    category: "Use of Hard-coded Credentials",
    truePositiveRate: 70,
    commonFalsePositives: [
      "Test fixtures and example code",
      "Placeholder values (changeme, xxx, TODO)",
      "Environment variable references (process.env.X)",
      "Default development credentials in docker-compose",
    ],
    confirmationEvidence: [
      "Real API keys/tokens in source code",
      "Production database passwords hardcoded",
      "Private keys embedded in source",
    ],
    owaspTop10: "A07:2021",
    mitreTop25Rank: 7,
  },
  {
    cweId: "CWE-352",
    category: "Cross-Site Request Forgery (CSRF)",
    truePositiveRate: 25,
    commonFalsePositives: [
      "APIs using Bearer token auth (CSRF not applicable)",
      "SameSite=Strict cookies configured",
      "Custom header requirements (X-Requested-With)",
      "Framework CSRF middleware enabled (Django, Rails, NestJS)",
    ],
    confirmationEvidence: [
      "Cookie-based auth without CSRF tokens",
      "State-changing GET requests",
      "No SameSite attribute on session cookies",
    ],
    owaspTop10: "A01:2021",
  },
  {
    cweId: "CWE-200",
    category: "Information Exposure",
    truePositiveRate: 30,
    commonFalsePositives: [
      "Intentional public API responses",
      "Error messages without stack traces in production",
      "Version headers removed via helmet",
      "Logging with PII redaction",
    ],
    confirmationEvidence: [
      "Stack traces returned to client in production",
      "Internal paths/IPs in error responses",
      "Sensitive data in URL query parameters",
      "Directory listing enabled",
    ],
    owaspTop10: "A04:2021",
  },
];

/**
 * Get CWE knowledge for a specific CWE ID
 */
export function getCweKnowledge(cweId: string): CweKnowledge | undefined {
  return CWE_KNOWLEDGE_BASE.find((k) => k.cweId === cweId);
}

/**
 * Determine if a finding needs deeper validation based on scan level
 */
export function requiresDeeperAnalysis(
  cweId: string,
  scanLevel: ScanLevel
): boolean {
  const config = SCAN_LEVELS[scanLevel];
  return config.requiresDeepValidation.includes(cweId);
}

/**
 * Calculate adjusted confidence for a finding based on scan level and CWE knowledge
 */
export function calculateAdjustedConfidence(
  baseConfidence: number,
  cweId: string,
  scanLevel: ScanLevel
): number {
  const knowledge = getCweKnowledge(cweId);
  if (!knowledge) return baseConfidence;

  // Deep scans have higher confidence
  const levelBonus = scanLevel === "DEEP" ? 15 : scanLevel === "LIGHTWEIGHT" ? 8 : 0;

  // Adjust by true positive rate
  const tpAdjustment = (knowledge.truePositiveRate - 50) / 5; // -10 to +4

  return Math.min(100, Math.max(0, baseConfidence + levelBonus + tpAdjustment));
}

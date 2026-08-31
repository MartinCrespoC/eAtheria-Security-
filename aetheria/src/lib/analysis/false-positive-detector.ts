/**
 * False Positive Detector
 * Filters out known false positives from vulnerability scan results.
 * Integrates scan-level knowledge (Static/L2/L3) for confidence scoring.
 */

import { prisma } from "@/lib/db";
import {
  ScanLevel,
  SCAN_LEVELS,
  getCweKnowledge,
  calculateAdjustedConfidence,
  requiresDeeperAnalysis,
} from "@/lib/analysis/scan-knowledge";

export interface VulnerabilityMatch {
  cweId: string;
  code: string;
  language: string;
  line: number;
  file: string;
  severity: string;
  /** Scan level context (defaults to STATIC) */
  scanLevel?: ScanLevel;
  /**
   * The raw vulnerable code snippet ONLY (no title/description/smartFix).
   * Used for high-precision rules that must not match prose or suggested fixes.
   */
  codeSnippet?: string;
}

export interface FalsePositiveResult {
  isFalsePositive: boolean;
  matchedPattern?: {
    id: string;
    description: string;
    reason: string;
    pattern: string;
    /** Provenance: "builtin" | "gitleaks" | "cwe" | "semgrep" | "juliet" | "manual". */
    source?: string;
    /** Pattern confidence (0-100) as ingested/curated. */
    confidence?: number;
    /** External rule id (for ingested patterns). */
    sourceRuleId?: string | null;
  };
  confidence: number; // 0-100
  /** Whether this finding needs deeper analysis to confirm */
  needsDeepValidation?: boolean;
  /** CWE knowledge context if available */
  cweContext?: {
    category: string;
    truePositiveRate: number;
    commonFalsePositives: string[];
  };
}

interface StoredPattern {
  id: string;
  language: string;
  pattern: string;
  description: string;
  reason: string;
  context: string | null;
  cweIds: unknown;
  examples: unknown;
  isActive: boolean;
  /** Provenance + ranking (FP Knowledge System). */
  source: string;
  confidence: number;
  sourceRuleId: string | null;
  category: string | null;
  createdAt?: Date;
  updatedAt?: Date;
}

export class FalsePositiveDetector {
  private patterns: Map<string, StoredPattern[]> = new Map();
  private initialized = false;

  /**
   * Initialize detector by loading all active patterns
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    const allPatterns = await prisma.falsePositivePattern.findMany({
      where: { isActive: true },
    });

    // Group patterns by language for faster lookup
    for (const pattern of allPatterns) {
      const existing = this.patterns.get(pattern.language) || [];
      existing.push(pattern);
      this.patterns.set(pattern.language, existing);
    }

    this.initialized = true;
    console.log(`✅ False Positive Detector initialized with ${allPatterns.length} patterns`);
  }

  /**
   * Check if a vulnerability match is a false positive
   */
  async checkVulnerability(match: VulnerabilityMatch): Promise<FalsePositiveResult> {
    if (!this.initialized) {
      await this.initialize();
    }

    const scanLevel: ScanLevel = match.scanLevel || "STATIC";
    const cweKnowledge = getCweKnowledge(match.cweId);
    // Ingested patterns must clear the scan-level confidence bar to mark a FP.
    const fpThreshold = SCAN_LEVELS[scanLevel].fpConfidenceThreshold;

    // ── High-precision deterministic rule: secret loaded from environment ──
    // A "hardcoded secret" finding is a false positive when the ACTUAL code line
    // reads the value from an environment variable / secret manager rather than
    // containing a literal. We inspect ONLY the raw codeSnippet (never the
    // description/smartFix, which legitimately mention env vars as the fix).
    const envLoadedFp = this.checkSecretFalsePositives(match);
    if (envLoadedFp) return envLoadedFp;

    // ── High-precision deterministic rules for non-secret CWEs whose snippet
    // already contains a correct mitigation (static markup sink, validated
    // redirect). Inspects ONLY the raw codeSnippet. ──
    const mitigatedFp = this.checkMitigatedFindings(match);
    if (mitigatedFp) return mitigatedFp;

    // Get patterns for this language, plus language-agnostic ("*") ingested
    // patterns (e.g. gitleaks secret allowlists that apply to every language).
    const lang = match.language.toLowerCase();
    const languagePatterns = [
      ...(this.patterns.get(lang) || []),
      ...(this.patterns.get("*") || []),
    ];

    // Check each pattern
    for (const pattern of languagePatterns) {
      // Check if CWE matches
      const cweIds = pattern.cweIds as string[];
      if (!cweIds.includes(match.cweId)) {
        continue;
      }

      // Ingested patterns (source !== "builtin") match ONLY the raw code snippet
      // to avoid false-FPs caused by coinciding with prose (title/desc/smartFix).
      // Curated builtin patterns keep the original behavior (match full text).
      const isIngested = pattern.source !== "builtin";
      const target = isIngested ? match.codeSnippet : match.code;
      if (!target) continue;

      // Confidence gate: ingested patterns must clear the scan-level threshold.
      if (isIngested && pattern.confidence < fpThreshold) continue;

      // Check if code matches pattern
      try {
        const regex = new RegExp(pattern.pattern, "i");
        if (regex.test(target)) {
          const baseConfidence = isIngested ? pattern.confidence : 85;
          const adjustedConfidence = calculateAdjustedConfidence(
            baseConfidence,
            match.cweId,
            scanLevel
          );

          return {
            isFalsePositive: true,
            matchedPattern: {
              id: pattern.id,
              description: pattern.description,
              reason: pattern.reason,
              pattern: pattern.pattern,
              source: pattern.source,
              confidence: pattern.confidence,
              sourceRuleId: pattern.sourceRuleId,
            },
            confidence: adjustedConfidence,
            needsDeepValidation: false, // Pattern matched = confirmed FP
            cweContext: cweKnowledge
              ? {
                  category: cweKnowledge.category,
                  truePositiveRate: cweKnowledge.truePositiveRate,
                  commonFalsePositives: cweKnowledge.commonFalsePositives,
                }
              : undefined,
          };
        }
      } catch (error) {
        console.error(`Invalid regex pattern: ${pattern.pattern}`, error);
      }
    }

    // No pattern matched — check if this CWE needs deeper validation
    const needsDeep = requiresDeeperAnalysis(match.cweId, scanLevel);

    return {
      isFalsePositive: false,
      confidence: 0,
      needsDeepValidation: needsDeep,
      cweContext: cweKnowledge
        ? {
            category: cweKnowledge.category,
            truePositiveRate: cweKnowledge.truePositiveRate,
            commonFalsePositives: cweKnowledge.commonFalsePositives,
          }
        : undefined,
    };
  }

  /**
   * High-precision rules: detect "hardcoded secret" findings that are NOT real
   * secrets. Only the raw codeSnippet is inspected (never prose or suggested
   * fixes, which legitimately mention env vars / placeholders).
   */
  private checkSecretFalsePositives(match: VulnerabilityMatch): FalsePositiveResult | null {
    const SECRET_CWES = ["CWE-798", "CWE-259", "CWE-321"];
    if (!SECRET_CWES.includes(match.cweId.trim())) return null;

    const snippet = match.codeSnippet || "";
    if (!snippet) return null;

    // (a) Code patterns that prove the value comes from the environment / a
    // secret manager, not a literal. Covers every language the platform scans.
    const ENV_LOAD_PATTERNS = [
      // ── JavaScript / TypeScript ──
      /\b(?:requireEnv|optionalEnv|getEnv|envOr)\s*\(\s*['"`]/, // requireEnv('KEY')
      /\bprocess\.env\.[A-Za-z_][A-Za-z0-9_]*/, // process.env.KEY
      /\bprocess\.env\s*\[\s*['"`]/, // process.env['KEY']
      /\bconfigService\.get(?:OrThrow)?\s*\(\s*['"`]/i, // NestJS ConfigService
      /\bConfigService\b[\s\S]{0,40}?\.get(?:OrThrow)?\s*\(\s*['"`]/, // ConfigService...get('KEY')
      // ── Python ──
      /\bos\.environ\b/, // os.environ['KEY']
      /\bos\.getenv\s*\(/, // os.getenv('KEY')
      // ── Java / Kotlin / Scala (JVM) ──
      /\bSystem\.getenv\s*\(/, // System.getenv("KEY")
      /\bSystem\.getProperty\s*\(\s*['"]/, // System.getProperty("KEY")
      /\bsys\.env\b/, // Scala sys.env("KEY")
      // ── C# / .NET ──
      /\bEnvironment\.GetEnvironmentVariable\s*\(/, // Environment.GetEnvironmentVariable("KEY")
      /\bConfigurationManager\.AppSettings\b/, // ConfigurationManager.AppSettings["KEY"]
      /\bConfiguration\s*\[\s*['"]/, // builder.Configuration["KEY"]
      // ── PHP ──
      /\bgetenv\s*\(\s*['"`]/, // getenv('KEY')
      /\benv\s*\(\s*['"`]/, // Laravel env('KEY')
      /\$_ENV\s*\[\s*['"`]/, // $_ENV['KEY']
      /\$_SERVER\s*\[\s*['"`]/, // $_SERVER['KEY']
      // ── Ruby ──
      /\bENV\s*\[\s*['"]/, // ENV['KEY']
      /\bENV\.fetch\s*\(\s*['"]/, // ENV.fetch('KEY')
      // ── Go ──
      /\bos\.Getenv\s*\(\s*['"`]/, // os.Getenv("KEY")
      /\bos\.LookupEnv\s*\(\s*['"`]/, // os.LookupEnv("KEY")
      // ── Rust ──
      /\b(?:std::)?env::var(?:_or)?\s*\(\s*['"`]/, // std::env::var("KEY")
      /\benv!\s*\(\s*['"`]/, // env!("KEY") (compile-time)
      // ── Swift ──
      /\bProcessInfo\.processInfo\.environment\b/, // ProcessInfo.processInfo.environment["KEY"]
      // ── C / C++ ──
      /\bstd::getenv\s*\(/, // std::getenv("KEY")
      // ── ABAP / SAP ──
      /\bcl_get_environment\b/i, // cl_get_environment=>get_value( )
      /\bGET\s+ENVIRONMENT\b/i, // GET ENVIRONMENT FIELD
    ];

    if (ENV_LOAD_PATTERNS.some((re) => re.test(snippet))) {
      return {
        isFalsePositive: true,
        matchedPattern: {
          id: "builtin-env-loaded-secret",
          description: "Secret loaded from environment variable",
          reason:
            "The flagged line reads the value from an environment variable / secret manager (e.g. requireEnv(), process.env, ConfigService) rather than containing a hardcoded literal. This is the correct CWE-798 remediation, not a vulnerability.",
          pattern: "env-load",
        },
        confidence: 95,
        needsDeepValidation: false,
      };
    }

    // (b) An empty-string value is a placeholder / initial form state, not a secret.
    // e.g. `inviteCode: ''` or `token = ""`. Only applies when there is no real
    // (4+ char, no-whitespace) string literal that could be the actual secret.
    if (/[:=]\s*['"]{2}\s*[,;}\)]?/.test(snippet) && !/['"][^\s'"]{4,}['"]/.test(snippet)) {
      return {
        isFalsePositive: true,
        matchedPattern: {
          id: "builtin-empty-string-placeholder",
          description: "Empty-string placeholder, not a secret",
          reason:
            "The flagged value is an empty string (initial form state / placeholder), not a hardcoded credential. There is no secret material in the code.",
          pattern: "empty-string",
        },
        confidence: 90,
        needsDeepValidation: false,
      };
    }

    // (c) The value is randomly generated at runtime (nanoid / uuid / randomBytes)
    // or is an ID-generation character set (customAlphabet) — NOT a hardcoded literal.
    const GENERATED_VALUE_PATTERNS = [
      /\bcustomAlphabet\s*\(/, // nanoid customAlphabet('abc...', n)
      /\b(?:nanoid|uuidv4|uuid|randomUUID|randomBytes|getRandomValues)\s*\(/,
      /\bcrypto\.randomBytes\s*\(/,
    ];
    if (GENERATED_VALUE_PATTERNS.some((re) => re.test(snippet))) {
      return {
        isFalsePositive: true,
        matchedPattern: {
          id: "builtin-generated-value",
          description: "Randomly-generated value, not a hardcoded secret",
          reason:
            "The flagged value is randomly generated at runtime (nanoid/uuid/randomBytes) or is an ID-generation character set (customAlphabet), not a hardcoded credential.",
          pattern: "generated-value",
        },
        confidence: 90,
        needsDeepValidation: false,
      };
    }

    return null;
  }

  /**
   * High-precision rules for non-secret CWEs where the raw codeSnippet already
   * contains a clear, correct mitigation. Only the raw codeSnippet is inspected
   * (never prose or suggested fixes).
   */
  private checkMitigatedFindings(match: VulnerabilityMatch): FalsePositiveResult | null {
    const snippet = match.codeSnippet || "";
    if (!snippet) return null;
    const cwe = match.cweId.trim();

    // True when the snippet contains user-controlled concatenation or template
    // interpolation — i.e. attacker input can reach the sink. The "static sink"
    // mitigations below only apply when this is FALSE.
    const dynamic = /['"`]\s*\+\s*|\+\s*['"`]|\$\{/.test(snippet);

    // ── CWE-79 (XSS): an HTML sink fed a STATIC markup literal — no template
    // interpolation and no concatenation → attacker input never reaches it. ──
    if (cwe === "CWE-79") {
      const STATIC_MARKUP_SINK =
        /\.(?:innerHTML|outerHTML)\s*=\s*['"`]\s*<|insertAdjacentHTML\s*\(\s*['"`][^'"`]*['"`]\s*,\s*['"`]\s*<|document\.write(?:ln)?\s*\(\s*['"`]\s*</;
      const hasInterpolation = /\$\{/.test(snippet);
      const hasConcat = /['"`]\s*\+\s*|\+\s*['"`]/.test(snippet);
      if (STATIC_MARKUP_SINK.test(snippet) && !hasInterpolation && !hasConcat) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-markup-sink",
            description: "Static markup literal assigned to HTML sink",
            reason:
              "The HTML sink (innerHTML/outerHTML/insertAdjacentHTML/document.write) is assigned a fixed markup literal with no user-controlled interpolation or concatenation. Static markup cannot carry attacker input, so this is not XSS.",
            pattern: "static-markup",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }

      // ── CWE-79 false positive: the flagged sink is an email SUBJECT line.
      // Email clients render the subject as plain text (never parsed as HTML),
      // so "HTML injection in email subject" is not XSS. The genuine subject
      // risk (SMTP header injection, CWE-113) is mitigated by stripping CR/LF;
      // HTML entity-encoding a subject would be WRONG (renders entities literally). ──
      const HTML_SINK =
        /(?:\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\bres\.send\b|\bres\.render\b|\bres\.write\b|\.html\s*\(|\bv-html\b|dangerouslySetInnerHTML|\.setHTML\s*\()/;
      const buildsSubject = /(?:const|let|var)\s+subject\s*=|\bsubject\s*[:=]/.test(snippet);
      const buildsHtmlBody = /(?:const|let|var)\s+html\s*=|\bhtml\s*:\s*['"`<]/.test(snippet);
      const emailContext =
        /\b(?:nodemailer|sendMail|mailOptions|sendEmail|createTransport|mailer|smtp|transporter)\b/i.test(snippet) ||
        /\\r\\n/.test(snippet) ||
        /\bsubject\b[\s\S]{0,80}?\b(?:dto|tenant|survey|recipient|invite)\b/i.test(snippet);
      if (buildsSubject && emailContext && !buildsHtmlBody && !HTML_SINK.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-email-subject-not-html-sink",
            description: "Email subject is a plain-text header, not an HTML sink",
            reason:
              "The flagged value flows into an email Subject header, which email clients display as plain text and never parse as HTML — so HTML/XSS injection is not possible here. The genuine subject risk (SMTP header injection, CWE-113) is mitigated by stripping CR/LF. HTML entity-encoding a subject would be incorrect (it would render entities literally).",
            pattern: "email-subject",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }

      // ── CWE-79 false positive: the flagged sink is textContent/innerText,
      // which never parse HTML — attacker markup is rendered as inert text. ──
      if (/\.(?:textContent|innerText)\s*=/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-text-sink",
            description: "Assignment to textContent/innerText (non-HTML sink)",
            reason:
              "textContent/innerText assign plain text and never parse HTML, so attacker-controlled markup is rendered inert and cannot execute. This is a correct XSS mitigation, not a vulnerability.",
            pattern: "text-sink",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-601 (Open Redirect): the redirect target is validated against a
    // trusted origin / allowlist (fail-closed) before redirecting → mitigated. ──
    if (cwe === "CWE-601") {
      const REDIRECT_VALIDATION = [
        /\bis(?:Trusted|Allowed|Safe|Valid)[A-Za-z]*\s*\(/i, // isTrustedTarget(url)
        /\.origin\s*===/, // targetUrl.origin === baseUrl.origin
        /\b(?:allowlist|whitelist|allowedHosts|trustedHosts|allowedOrigins|trustedOrigins)[\s\S]{0,40}?\.(?:includes|some|has|indexOf)\s*\(/i,
      ];
      if (REDIRECT_VALIDATION.some((re) => re.test(snippet))) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-validated-redirect",
            description: "Redirect target validated against trusted origin/allowlist",
            reason:
              "The redirect target is validated (trusted-target check, exact origin match, or allowlist lookup) before redirecting, rejecting untrusted targets. This is the correct CWE-601 remediation, not an open redirect.",
            pattern: "validated-redirect",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }

      // ── CWE-601 false positive: redirect to a static string-literal target —
      // no user input reaches the redirect location. ──
      if (!dynamic && /redirect\s*\(\s*["'`][^"'`]*["'`]\s*\)/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-redirect",
            description: "Redirect to a static string-literal target",
            reason:
              "The redirect target is a fixed string literal with no user-controlled concatenation or interpolation, so it cannot be turned into an open redirect.",
            pattern: "static-redirect",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-89 (SQL Injection): a parameterized query — the SQL string carries
    // bind placeholders ($1 / ? / :name) and the values are passed separately. ──
    if (cwe === "CWE-89") {
      const PARAM_SQL =
        /(?:query|execute|run|all|get|prepare)\s*\(\s*["'`][^"'`]*(?:\$\d+|\?(?!\w)|:[a-zA-Z_]\w*)[^"'`]*["'`]\s*,/i;
      if (!dynamic && PARAM_SQL.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-parameterized-sql",
            description: "Parameterized SQL query with bound values",
            reason:
              "The query uses bind placeholders ($1/?/:name) with the values passed as a separate bound argument, so user input is never concatenated into the SQL text. This is the correct CWE-89 remediation.",
            pattern: "parameterized-sql",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-78 (OS Command Injection): exec/spawn with a single static string
    // literal command — no attacker-controlled segment reaches the shell. ──
    if (cwe === "CWE-78") {
      // exec/execSync: the second argument is an options object/callback, so a
      // static literal first arg really is safe. spawn/execFile: the second
      // argument is the ARGS ARRAY — it can carry tainted values
      // (`spawn('cmd.exe', ['/C', editor])` — CVE-2018-6342), so only the
      // single-argument form (`spawn('ls')`) is suppressible.
      const STATIC_CMD =
        /(?:exec|execSync)\s*\(\s*["'`][^"'`]*["'`]\s*[,)]/;
      const STATIC_CMD_SINGLE_ARG =
        /(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*["'`][^"'`]*["'`]\s*\)/;
      if (
        !dynamic &&
        (STATIC_CMD.test(snippet) || STATIC_CMD_SINGLE_ARG.test(snippet))
      ) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-command",
            description: "Static string-literal command (no user input)",
            reason:
              "The command is a fixed string literal with no concatenation or template interpolation, so no attacker-controlled value reaches the shell. This is not OS command injection.",
            pattern: "static-command",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-22 (Path Traversal): a filesystem call whose path is a static string
    // literal — no user input is concatenated into the path. ──
    if (cwe === "CWE-22") {
      const STATIC_PATH =
        /(?:readFileSync|readFile|createReadStream|accessSync|statSync|openSync|existsSync)\s*\(\s*["'`][^"'`]*["'`]\s*[,)]/;
      if (!dynamic && STATIC_PATH.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-path",
            description: "Static string-literal filesystem path (no user input)",
            reason:
              "The filesystem path is a fixed string literal with no user-controlled concatenation or interpolation, so it cannot escape the intended directory. This is not path traversal.",
            pattern: "static-path",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-918 (SSRF): an outbound request to a static URL literal — the host
    // is developer-controlled, not user-supplied. ──
    if (cwe === "CWE-918") {
      const STATIC_URL =
        /(?:fetch|axios|got|request|https?\.get)\s*\(\s*["'`]https?:\/\/[^"'`]*["'`]\s*[,)]/;
      if (!dynamic && STATIC_URL.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-url",
            description: "Outbound request to a static URL literal",
            reason:
              "The request URL is a fixed string literal with no user-controlled concatenation or interpolation, so the target host cannot be attacker-directed. This is not SSRF.",
            pattern: "static-url",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-94 (Code Injection): JSON.parse deserializes DATA and never executes
    // code, so a "code injection" finding on JSON.parse is a false positive. ──
    if (cwe === "CWE-94") {
      if (/JSON\.parse\s*\(/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-json-parse-not-code",
            description: "JSON.parse is data deserialization, not code execution",
            reason:
              "JSON.parse only parses JSON data; it never evaluates or executes code (unlike eval/new Function). A code-injection finding on JSON.parse is a false positive.",
            pattern: "json-parse-not-code",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-327 (Weak Crypto): a strong hash algorithm (SHA-256+) is in use —
    // this is the correct primitive, not a broken/risky algorithm. (Weak hashes
    // such as MD5/SHA-1 do NOT match and remain flagged.) ──
    if (cwe === "CWE-327") {
      const STRONG_HASH =
        /createHash\s*\(\s*["'`](?:sha256|sha384|sha512|sha3-\d+|blake2[bs]\d+)["'`]/i;
      if (STRONG_HASH.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-strong-hash",
            description: "Strong hash algorithm (SHA-256+) in use",
            reason:
              "The code uses a cryptographically strong hash (SHA-256/384/512, SHA-3, BLAKE2). Weak algorithms (MD5/SHA-1) are still flagged; this strong usage is not CWE-327.",
            pattern: "strong-hash",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-611 (XXE): XML parsing with external-entity substitution disabled
    // (noent:false) — the XXE mitigation is present in the snippet. ──
    if (cwe === "CWE-611") {
      if (/noent\s*:\s*false/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-xxe-entities-disabled",
            description: "XML external-entity substitution disabled (noent:false)",
            reason:
              "The XML parser is configured with noent:false (entity substitution disabled), which is the correct XXE mitigation. Entity expansion attacks are not possible here.",
            pattern: "xxe-entities-disabled",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-347 (JWT verification): an explicit `algorithms: […]` allowlist in
    // the verifier config IS the mitigation for algorithm-confusion / 'none'
    // downgrade attacks. Flagging the pinned list as the vulnerability inverts
    // the finding (the vulnerable shape is the ABSENCE of this option). ──
    if (cwe === "CWE-347") {
      if (/algorithms\s*:\s*\[\s*['"][A-Za-z0-9]+['"]/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-jwt-algorithms-pinned",
            description: "JWT accepted-algorithm allowlist pinned (mitigation present)",
            reason:
              "The verifier config pins the accepted JWT algorithms (algorithms: […]), which is the exact mitigation for CWE-347 algorithm-confusion/downgrade attacks. Tokens with a different or 'none' algorithm are rejected.",
            pattern: "jwt-algorithms-pinned",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-502 (Deserialization): JSON.parse is a safe data deserializer (no
    // code execution / gadget chain), unlike unserialize/pickle/ObjectInputStream. ──
    if (cwe === "CWE-502") {
      if (/JSON\.parse\s*\(/.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-json-parse-safe-deserialize",
            description: "JSON.parse is safe data deserialization",
            reason:
              "JSON.parse deserializes plain JSON data and cannot instantiate arbitrary objects or execute code (unlike unserialize/pickle/ObjectInputStream). This is not insecure deserialization.",
            pattern: "json-parse-safe-deserialize",
          },
          confidence: 90,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-1336 (SSTI): render_template("file.html", ...) loads a developer-
    // controlled template FILE. (render_template_string does NOT match — its
    // template is a string that may carry attacker input.) ──
    if (cwe === "CWE-1336") {
      const STATIC_TEMPLATE = /render_template\s*\(\s*["'][^"'`]*["']\s*,/;
      if (!dynamic && STATIC_TEMPLATE.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-static-template-file",
            description: "Server-side template loaded from a static file",
            reason:
              "render_template() loads a developer-controlled template file; the template itself is not user-supplied, so server-side template injection is not possible here.",
            pattern: "static-template-file",
          },
          confidence: 88,
          needsDeepValidation: false,
        };
      }
    }

    // ── CWE-1321 (Prototype Pollution): object spread / literal construction
    // creates a NEW object and never recursively merges into an existing
    // prototype (unlike _.merge / Object.assign / __proto__ writes). ──
    if (cwe === "CWE-1321") {
      const UNSAFE_MERGE =
        /(?:_\.merge|_\.extend|_\.defaultsDeep|_\.set|lodash\.merge|Object\.assign|__proto__|constructor\s*\.\s*prototype|\[\s*["'`]__proto__["'`]\s*\])/;
      if (/\{\s*\.\.\./.test(snippet) && !UNSAFE_MERGE.test(snippet)) {
        return {
          isFalsePositive: true,
          matchedPattern: {
            id: "builtin-object-spread-safe",
            description: "Object spread/literal (no recursive merge)",
            reason:
              "Object spread ({ ...x }) builds a new object and does not recursively merge into an existing object's prototype, so it cannot cause prototype pollution. Only recursive merges (_.merge/Object.assign) with user input are flagged.",
            pattern: "object-spread-safe",
          },
          confidence: 85,
          needsDeepValidation: false,
        };
      }
    }

    return null;
  }

  /**
   * Batch check multiple vulnerabilities
   */
  async checkBatch(matches: VulnerabilityMatch[]): Promise<Map<number, FalsePositiveResult>> {
    const results = new Map<number, FalsePositiveResult>();

    for (let i = 0; i < matches.length; i++) {
      const result = await this.checkVulnerability(matches[i]);
      results.set(i, result);
    }

    return results;
  }

  /**
   * Get statistics about false positive detection
   */
  getStats() {
    const totalPatterns = Array.from(this.patterns.values()).reduce(
      (sum, patterns) => sum + patterns.length,
      0
    );

    return {
      initialized: this.initialized,
      totalPatterns,
      languagesCovered: this.patterns.size,
      languages: Array.from(this.patterns.keys()),
    };
  }

  /**
   * Reload patterns from database
   */
  async reload(): Promise<void> {
    this.patterns.clear();
    this.initialized = false;
    await this.initialize();
  }
}

// Singleton instance
export const falsePositiveDetector = new FalsePositiveDetector();

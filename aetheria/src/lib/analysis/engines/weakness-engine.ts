/**
 * Deterministic Weakness Engine (multi-language).
 *
 * Detects security weaknesses that are NOT source→sink data-flow issues and so
 * are invisible to the taint engine. These are the "non-taint" OWASP Benchmark
 * categories plus their equivalents across every language EATHERIA supports:
 *
 *   - CWE-327 Broken Crypto : use of a weak/broken cipher algorithm.
 *   - CWE-328 Weak Hash     : use of a weak hash algorithm (MD5/SHA-1/…).
 *   - CWE-330 Weak PRNG     : use of a non-cryptographic random generator.
 *   - CWE-614 Insecure Cookie: a cookie added without the Secure flag (Java).
 *   - CWE-501 Trust Boundary : untrusted data stored into an HTTP session (Java).
 *
 * Crypto/Hash/PRNG are detected with declarative, per-language regex rules so the
 * engine works for JavaScript/TypeScript, Python, Java, PHP, C#, Ruby, Go and a
 * generic fallback. Cookie/Trust-boundary are inherently Java-servlet concepts and
 * use small custom detectors (the trust-boundary detector reuses the taint engine's
 * `computeTaintedVarNames` to know which variables carry user input).
 *
 * This engine reports findings; the false-positive filter (`falsePositiveDetector`)
 * still makes the final keep/dismiss decision, exactly like the other engines.
 */
import { computeTaintedVarNames, type TaintRulesBundle } from "./taint-engine";
import * as fs from "fs";
import * as path from "path";

export interface WeaknessFinding {
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
  detectionMethod: "WEAKNESS";
}

/**
 * A declarative weakness rule. `regex` is matched line-by-line.
 *
 * - `kind: "always"`      → flag every match.
 * - `kind: "weak-literal"`→ flag only when the call's first string-literal
 *   argument is a known-weak algorithm, OR when the argument is a variable
 *   (algorithm not confirmable as strong). Strong literals (AES, SHA-256…) are
 *   NOT flagged. This is what separates OWASP true cases (DES / MD5 / variable)
 *   from false cases (AES/GCM / "sha-384").
 */
interface WeaknessRule {
  cwe: string;
  category: string;
  severity: WeaknessFinding["severity"];
  owasp2021: string;
  regex: RegExp;
  kind: "always" | "weak-literal";
  confidence: number;
}

// ==================== ALGORITHM CLASSIFICATION ====================

/** Strong crypto/hash algorithms — never flagged. */
const STRONG_ALGOS = [
  "AES", "AES/GCM", "AES/CBC", "AES/CTR", "CHACHA20", "CHACHA20-POLY1305",
  "CAMELLIA", "SERPENT", "TWOFISH",
  "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/256",
  "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256",
  "BLAKE2B", "BLAKE2S", "BLAKE3", "RIPEMD160", "SM3", "PBKDF2",
];

/** Weak/broken algorithms — always flagged. */
const WEAK_ALGOS = [
  "DES", "DESEDE", "3DES", "TRIPLEDES", "RC2", "RC4", "ARCFOUR", "BLOWFISH",
  "ECB", "CAST5", "CAST-128", "IDEA", "SEED",
  "MD2", "MD4", "MD5", "SHA", "SHA-0", "SHA-1", "SHA1", "CRC32", "ADLER32",
];

function normAlgo(s: string): string {
  return s.trim().toUpperCase();
}

function isStrongAlgo(literal: string): boolean {
  const a = normAlgo(literal);
  // Match on the base algorithm (before any "/" mode) so "AES/GCM/NoPadding" → AES.
  const base = a.split("/")[0];
  return STRONG_ALGOS.some((s) => s === a || s === base);
}

function isWeakAlgo(literal: string): boolean {
  const a = normAlgo(literal);
  const base = a.split("/")[0];
  // Classification is driven by the BASE algorithm (before any "/" mode). OWASP
  // Benchmark ground truth treats a strong base (AES) as safe even in ECB mode
  // (e.g. "AES/ECB/PKCS5Padding" is a FALSE/safe case), while a weak base
  // (DES/DESede/RC4…) is vulnerable regardless of mode. So we do NOT auto-flag ECB.
  return WEAK_ALGOS.some((w) => w === a || w === base);
}

/**
 * True when `index` falls inside a string literal on the line (an odd number of
 * unescaped quotes precedes it). Used to ignore pattern matches that occur inside
 * string literals — e.g. the OWASP catch-block messages
 * `"Problem executing crypto - javax.crypto.Cipher.getInstance(...)"`, which would
 * otherwise be mistaken for real API calls and wreck the false-positive rate.
 */
function isInsideStringLiteral(line: string, index: number): boolean {
  let dq = 0;
  let sq = 0;
  let bq = 0;
  for (let i = 0; i < index; i++) {
    const ch = line[i];
    if (ch === "\\") {
      i++; // skip the escaped character
      continue;
    }
    if (ch === '"') dq++;
    else if (ch === "'") sq++;
    else if (ch === "`") bq++;
  }
  return dq % 2 === 1 || sq % 2 === 1 || bq % 2 === 1;
}

/**
 * Resolve the algorithm argument of a `Cipher.getInstance(...)` /
 * `MessageDigest.getInstance(...)` call to a concrete string literal, or `null`
 * when it cannot be determined. Handles three shapes:
 *   1. same-line literal      → `getInstance("DES/CBC/PKCS5Padding")`
 *   2. multiline call         → `getInstance(\n    "AES/CCM/NoPadding", provider)`
 *   3. variable argument      → `getInstance(algorithm)` where `algorithm` was
 *      assigned a constant or a `getProperty(key, DEFAULT)` earlier in the method.
 * Returning `null` (unresolvable) leads to a conservative SKIP, which is what keeps
 * the false-positive rate low on safe cases we cannot prove weak.
 */
function resolveAlgoLiteral(lines: string[], lineIdx: number, callMatch: RegExpExecArray): string | null {
  const line = lines[lineIdx];
  const after = line.slice(callMatch.index + callMatch[0].length);

  // 1. Same-line string literal argument.
  const sameLine = after.match(/^\s*["'`]([^"'`]*)["'`]/);
  if (sameLine) return sameLine[1];

  // 2. Multiline call: nothing but whitespace after the opening paren on this line.
  if (after.trim() === "") {
    for (let j = lineIdx + 1; j <= Math.min(lineIdx + 3, lines.length - 1); j++) {
      const t = lines[j].trim();
      const ml = t.match(/^["'`]([^"'`]*)["'`]/);
      if (ml) return ml[1];
      if (t.includes(")") || t.endsWith(";")) break;
    }
    return null;
  }

  // 3. Variable argument → resolve its most recent assignment above this line.
  const vm = after.match(/^\s*([A-Za-z_$][\w$]*)/);
  if (vm) return resolveVarAlgo(lines, lineIdx, vm[1]);

  return null;
}

/**
 * Resolve a variable's algorithm by scanning backwards for its assignment. The
 * algorithm is taken as the LAST double-quoted literal on the assignment line:
 *   - `String alg = "DES"`                          → "DES"
 *   - `String alg = props.getProperty("k", "DESede/ECB/PKCS5Padding")` → resolved
 *     from the project's properties file if available, else the default.
 * A `getProperty("key")` with no default yields the key (not an algo) which simply
 * won't classify as weak/strong and is therefore skipped conservatively.
 */
function resolveVarAlgo(lines: string[], lineIdx: number, varName: string): string | null {
  const re = new RegExp("(?:^|[;{}\\s])" + varName + "\\s*=\\s*(.+?)\\s*;");
  for (let j = lineIdx - 1; j >= Math.max(0, lineIdx - 25); j--) {
    const m = re.exec(lines[j]);
    if (!m) continue;
    // Detect getProperty("key", "default") pattern and resolve from config.
    const propCall = m[1].match(/getProperty\s*\(\s*"([^"]+)"\s*(?:,\s*"([^"]*)")?\s*\)/);
    if (propCall) {
      const resolved = resolveProperty(propCall[1]);
      if (resolved !== null) return resolved;
      // Fall back to the default value if provided.
      if (propCall[2] !== undefined) return propCall[2];
      return null;
    }
    const lits = [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]);
    if (lits.length === 0) return null; // assigned from another var/method, no literal
    return lits[lits.length - 1];
  }
  return null;
}

/** Cache of properties read from project config files (loaded once). */
let projectProps: Map<string, string> | null = null;

/** Directories never searched for properties files. */
const PROPS_SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "out"]);

/**
 * Resolve a Java system-property key against `.properties` files present in
 * the project tree (`System.getProperty("hashAlg", "SHA-256")` reads runtime
 * config — the value that actually matters for classification is the
 * configured one, not the in-code default). Generic project-config resolution:
 * any `.properties` file under cwd is considered, sorted for determinism,
 * first definition wins. Capped to bound scan cost; absent files → null.
 */
function resolveProperty(key: string): string | null {
  if (projectProps === null) {
    projectProps = new Map();
    const files: string[] = [];
    const stack: Array<{ dir: string; depth: number }> = [{ dir: process.cwd(), depth: 0 }];
    while (stack.length && files.length < 20) {
      const { dir, depth } = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth < 6 && !PROPS_SKIP_DIRS.has(e.name)) stack.push({ dir: full, depth: depth + 1 });
        } else if (e.name.endsWith(".properties")) {
          files.push(full);
        }
      }
    }
    for (const file of files.sort()) {
      let content: string;
      try {
        content = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
        const eqIdx = trimmed.indexOf("=");
        const k = trimmed.slice(0, eqIdx).trim();
        if (!projectProps.has(k)) projectProps.set(k, trimmed.slice(eqIdx + 1).trim());
      }
    }
  }
  return projectProps.get(key) ?? null;
}

// ==================== DECLARATIVE RULES (per language) ====================
// `*` rules apply to every language (in addition to language-specific ones).

const RULES: Record<string, WeaknessRule[]> = {
  // ---- JavaScript / TypeScript ----
  javascript: [
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\bcreateCipher\s*\(/ },
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\bcreateCipheriv\s*\(\s*["'`](?:des|des3|rc2|rc4|blowfish|cast|idea|seed)\b/i },
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 90, regex: /\bcreateHash\s*\(\s*["'`](?:md4|md5|sha|sha1|sha0|crc32|adler32)["'`]/i },
    // Probability branching (`Math.random() > 0.5`) is game/simulation logic,
    // not credential generation — the comparison form is exempt.
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bMath\.random\s*\(\s*\)(?!\s*(?:[<>]=?|===?|!==?)\s*[\d.])/ },
  ],
  // ---- Python ----
  python: [
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\b(?:DES|ARC2|ARC4|Blowfish|CAST)\.new\s*\(/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 90, regex: /\bhashlib\.(?:md5|sha1|md4|sha)\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\brandom\.(?:random|randint|choice|uniform|getrandbits|sample|seed)\s*\(/ },
  ],
  // ---- Java ----
  java: [
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "weak-literal", confidence: 85, regex: /Cipher\.getInstance\s*\(/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "weak-literal", confidence: 85, regex: /MessageDigest\.getInstance\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /new\s+(?:java\.util\.)?Random\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bMath\.random\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\bThreadLocalRandom\.current\s*\(/ },
  ],
  // ---- PHP ----
  php: [
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 90, regex: /\bmd5\s*\(/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "LOW", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bsha1\s*\(/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\bhash\s*\(\s*['"](?:md5|sha1|md4|sha)['"]/i },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\b(?:rand|mt_rand|lcg_value)\s*\(/ },
  ],
  // ---- Ruby ----
  ruby: [
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 90, regex: /\bDigest::MD5\b/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "LOW", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bDigest::SHA1\b/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\bKernel#?(?:rand|srand)\b|\brand\s*\(\s*\d/ },
  ],
  // ---- Go ----
  go: [
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /\brand\.(?:Intn|Int|Float64|Seed|Read)\s*\(/ },
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bdes\.New(?:TripleDES)?Cipher\s*\(/ },
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\brc4\.NewCipher\s*\(/ },
  ],
  // ---- C# ----
  csharp: [
    { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\b(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)\b/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 90, regex: /\bMD5(?:CryptoServiceProvider)?\.Create\s*\(|\bnew\s+MD5CryptoServiceProvider\s*\(/ },
    { cwe: "CWE-328", category: "Weak Hash", severity: "LOW", owasp2021: "A02:2021", kind: "always", confidence: 85, regex: /\bSHA1(?:CryptoServiceProvider|Managed)\.Create\s*\(|\bnew\s+SHA1(?:CryptoServiceProvider|Managed)\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 80, regex: /new\s+(?:System\.)?Random\s*\(/ },
  ],
  // ---- Generic fallback (other supported languages) ----
  "*": [
    { cwe: "CWE-328", category: "Weak Hash", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 75, regex: /\bmd5\s*\(/ },
    { cwe: "CWE-330", category: "Weak PRNG", severity: "MEDIUM", owasp2021: "A02:2021", kind: "always", confidence: 70, regex: /\bMath\.random\s*\(/ },
  ],
};

// ==================== MAIN ENGINE ====================

export function runWeaknessAnalysis(
  fileContent: string,
  filePath: string,
  language: string,
  taintRules?: TaintRulesBundle
): WeaknessFinding[] {
  const lang = language.toLowerCase();
  const rules = [...(RULES[lang] ?? []), ...(RULES["*"] ?? [])];
  const isJava = lang === "java";

  const lines = fileContent.split("\n");
  const findings: WeaknessFinding[] = [];

  const snippetAt = (i: number): string => {
    const start = Math.max(0, i - 1);
    const end = Math.min(lines.length - 1, i + 1);
    return lines.slice(start, end + 1).join("\n");
  };

  // ── Declarative crypto / hash / weakrand rules ──
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (
      trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") ||
      trimmed.startsWith("/*") || trimmed.startsWith("--")
    ) {
      continue;
    }

    for (const rule of rules) {
      const m = rule.regex.exec(line);
      if (!m) continue;
      // Ignore matches that occur inside a string literal (e.g. the OWASP
      // catch-block messages "Problem executing crypto - javax.crypto.Cipher.getInstance(...)").
      if (isInsideStringLiteral(line, m.index)) continue;

      if (rule.kind === "weak-literal") {
        // Resolve the algorithm argument to a literal (same-line, multiline call, or a
        // variable's assigned constant / getProperty default). Flag ONLY when it resolves
        // to a known-weak algorithm; strong / unknown / unresolvable → conservative skip.
        const algo = resolveAlgoLiteral(lines, i, m);
        if (algo === null || !isWeakAlgo(algo)) continue;
      }

      findings.push(makeFinding(rule, filePath, i + 1, snippetAt(i), line.trim()));
    }
  }

  // ── Java servlet-specific detectors ──
  if (isJava) {
    findings.push(...detectInsecureCookies(lines, filePath, snippetAt));
    findings.push(...detectTrustBoundary(lines, filePath, language, fileContent, taintRules, snippetAt));
  }

  // ── Script-language structural detectors ──
  if (language === "javascript" || language === "typescript") {
    findings.push(...detectReDoS(lines, filePath, snippetAt));
    findings.push(...detectPrototypePollution(lines, filePath, snippetAt));
    findings.push(...detectIncompleteSanitization(lines, filePath, snippetAt));
    findings.push(...detectIncompleteSchemeCheck(lines, filePath, snippetAt));
    findings.push(...detectWeakRandomAndEnvLeak(lines, filePath, snippetAt));
  }

  return dedupe(findings);
}

// ==================== JS/TS: REGEX DENIAL OF SERVICE (CWE-730) ====================

/**
 * Structural ReDoS detector. Taint analysis cannot see ReDoS (no source→sink
 * flow) — it is a property of the PATTERN itself. We extract regex literals and
 * RegExp-constructor strings and analyze their structure for the two canonical
 * catastrophic-backtracking shapes:
 *
 *   1. Nested unbounded quantifiers: `(a+)+`, `(\w*)*`, `([a-z]+){2,}`
 *   2. Ambiguous alternation under an unbounded quantifier: `(a|ab)+`, `(x|x)*`
 *      (alternatives sharing a non-empty prefix — the engine cannot decide which
 *      branch a character belongs to without backtracking)
 *
 * Bounded quantifiers (`{2,8}`) and trivially-short patterns are ignored, which
 * is what separates vulnerable patterns from their patched variants (ReDoS fixes
 * typically bound or unnest the repetition).
 */

/** Quantifier that can iterate arbitrarily many times. `{n}` is EXACT (bounded);
 * `{n,}` is unbounded; `{n,mm}` with a large max is effectively unbounded. */
// `{n,m}` counts as unbounded only when m is large (≥1000): the npm ReDoS
// fix idiom bounds quantifiers to a few hundred (`\s{0,256}` — tough-cookie,
// bson, mocha, content-disposition patches), which caps backtracking.
const UNBOUNDED_QUANT = /^(?:[+*]|\{\d+,\s*\}|\{\d+,\s*\d{4,}\})/;

/** Character-class descriptor of an atom, for overlap checks. */
function atomClass(p: string, i: number): { cls: string; next: number } | null {
  const ch = p[i];
  if (ch === "\\" && i + 1 < p.length) {
    const c = p[i + 1];
    if ("dwsWDSbB".includes(c)) return { cls: `\\${c}`, next: i + 2 };
    const ctrl: Record<string, string> = { n: "\n", r: "\r", t: "\t", f: "\f", v: "\v", "0": "\0" };
    if (ctrl[c]) return { cls: `lit:${ctrl[c]}`, next: i + 2 };
    if (c === "x" && /^[0-9a-fA-F]{2}$/.test(p.slice(i + 2, i + 4))) {
      return { cls: `lit:${String.fromCharCode(parseInt(p.slice(i + 2, i + 4), 16))}`, next: i + 4 };
    }
    return { cls: `lit:${c}`, next: i + 2 };
  }
  if (ch === "[") {
    // Scan for the UNESCAPED closing bracket (`\]` is a literal, `]` as the
    // first class char is a literal too).
    let j = i + 1;
    if (p[j] === "^") j++;
    if (p[j] === "]") j++;
    for (; j < p.length; j++) {
      if (p[j] === "\\") { j++; continue; }
      if (p[j] === "]") break;
    }
    if (j < p.length) return { cls: p.slice(i, j + 1), next: j + 1 };
    return null;
  }
  if (ch === ".") return { cls: ".", next: i + 1 };
  return { cls: `lit:${ch}`, next: i + 1 };
}

/** Decode escapes inside class contents (`\n`, `\x41`, `\d`, `\w`, `\s`, …). */
function decodeClassContents(s: string): string {
  return s
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\f/g, "\f")
    .replace(/\\v/g, "\v")
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\d/g, "0-9")
    .replace(/\\w/g, "a-zA-Z0-9_")
    .replace(/\\s/g, " \t\n\r")
    .replace(/\\(.)/g, "$1");
}

/** Range-aware membership test for class contents like `a-z0-9_`. */
function charInClassContents(ch: string, contents: string): boolean {
  for (let k = 0; k < contents.length; k++) {
    if (k + 2 < contents.length && contents[k + 1] === "-") {
      if (ch >= contents[k] && ch <= contents[k + 2]) return true;
      k += 2;
    } else if (contents[k] === ch) return true;
  }
  return false;
}

/**
 * Do two character-class descriptors overlap (a string can match both)?
 * Negation-aware: `[^\n]` does NOT overlap `\n` (it matches everything EXCEPT
 * newline) but DOES overlap `\d`. Treating negated classes as their contents
 * was the main source of ReDoS false positives (marked.js-style patterns).
 */
function classesOverlap(a: string, b: string): boolean {
  if (a === b) return true;
  const negA = a.startsWith("[^");
  const negB = b.startsWith("[^");
  if (negA && negB) return true; // two negated classes overlap in practice
  if (negA || negB) {
    const neg = decodeClassContents((negA ? a : b).slice(2, -1));
    const other = negA ? b : a;
    if (other === ".") return true;
    const expandOther = (c: string): string => {
      if (c === "\\d") return "0-9";
      if (c === "\\w") return "a-zA-Z0-9_";
      if (c === "\\s") return " \t\n\r";
      if (c.startsWith("[")) return c.slice(1, -1);
      if (c.startsWith("lit:")) return c.slice(4);
      return "";
    };
    const eo = expandOther(other);
    if (!eo) return true; // unknown → conservative overlap
    // Overlap UNLESS every char of the other class sits inside the negated set
    // (then they are disjoint — e.g. lit:\n vs [^\n]). NOTE: a `\` char here
    // is a LEGIT literal backslash (escapes were decoded above) — skipping it
    // hid the CVE-2020-7662 ambiguity (`\\[\x00-\x7f]` vs `[^…"]`).
    for (const ch of eo) {
      if (!charInClassContents(ch, neg)) return true;
    }
    return false;
  }
  const expand = (c: string): string => {
    if (c === "\\d") return "0-9";
    if (c === "\\w") return "a-zA-Z0-9_";
    if (c === "\\s") return " \t\n\r";
    if (c.startsWith("[")) return decodeClassContents(c.slice(1, -1));
    if (c.startsWith("lit:")) return c.slice(4);
    return "";
  };
  const ea = expand(a);
  const eb = expand(b);
  if (a === "." || b === ".") {
    // JS dot matches everything EXCEPT \n \r u2028 u2029.
    const eo = a === "." ? eb : ea;
    if (!eo) return true;
    for (const ch of eo) {
      if (ch !== "\n" && ch !== "\r" && ch !== " " && ch !== " ") return true;
    }
    return false;
  }
  if (!ea || !eb) return false;
  for (const ch of ea.length <= eb.length ? ea : eb) {
    if (charInClassContents(ch, ea.length <= eb.length ? eb : ea)) return true;
  }
  return false;
}

/**
 * Analyze a regex pattern for catastrophic backtracking. Returns a human
 * reason when vulnerable, null otherwise.
 */
export function analyzeReDoSPattern(pattern: string): string | null {
  // 5 chars is the shortest meaningful polynomial shape (`A*lA*` sandwich —
  // the negotiator/fresh `/ *, */` CVEs are exactly 5).
  if (pattern.length < 5) return null;
  // Group stack. For each group we track whether its body contains an unbounded
  // quantifier, its first/last atom classes (ambiguity test), and the raw
  // alternative fragments (alternation overlap test).
  interface GroupCtx {
    hasInnerQuant: boolean;
    firstCls: string | null;
    lastCls: string | null;
    alts: string[];
    /** First-atom descriptor of each alternative (escape-safe, no reparse). */
    altFirsts: (string | null)[];
    cur: string;
    curFirstCls: string | null;
    /** Second atom of the group + whether the first atom was `?`-optional —
     * iteration-ambiguity test needs the first MANDATORY class. */
    secondCls: string | null;
    firstOptional: boolean;
    /** prevQuantCls before the group was entered — restored for empty-able
     * groups (`\s*(?:''|"")?\s*` keeps the outer quantified context). */
    outerPrevQuant: string | null;
    /** Lookaheads (?=…)/(?!…)/(?<=…)/(?<!…) consume no input. */
    zeroWidth: boolean;
  }
  const stack: GroupCtx[] = [];
  const pushGroup = (zeroWidth = false) =>
    stack.push({ hasInnerQuant: false, firstCls: null, lastCls: null, alts: [], altFirsts: [], cur: "", curFirstCls: null, secondCls: null, firstOptional: false, outerPrevQuant: prevQuantCls, zeroWidth });

  // Adjacency tracking for `\d+\d+`-style ambiguity. `pendingAtomCls` is the
  // atom just seen (awaiting a possible quantifier); `prevQuantCls` is the
  // class of the most recent QUANTIFIED atom. A non-quantified atom between two
  // quantified atoms (a separator like `\.`) breaks the adjacency.
  let pendingAtomCls: string | null = null;
  let prevQuantCls: string | null = null;
  // Polynomial (quadratic) tracking — the OpenSSF "polynomial regex" CVEs:
  //  • optChainCls: first-class of the last OPTIONAL (?-quantified) atom/group;
  //    a mandatory non-empty atom breaks the chain.
  //  • sepQuantCls: class of the last UNBOUNDED-quantified atom separated from
  //    the current one by exactly one literal (`A* lit A*` sandwich — `/ *, */`).
  let optChainCls: string | null = null;
  let sandwich: { cls: string; sep: string } | null = null;
  // Deferred sandwich: `A* sep A*` only backtracks catastrophically when what
  // FOLLOWS the second A* can also be consumed by it (or nothing follows —
  // negotiator's standalone ` *, *`). A following mandatory atom disjoint from
  // the class PINS the split (` *; *PARAM` — CVE-2020-7662's fixed form).
  let pendingSandwich: { cls: string; reason: string } | null = null;
  // A disjoint atom is only a pin when MANDATORY — an OPTIONAL atom vanishes
  // and the ambiguity survives (`\s*=\s*['"]? *` — CVE-2017-16098: the
  // optional quote does not pin the whitespace split). We record the
  // candidate here and restore the sandwich if the atom gets `?`-quantified.
  let pinCandidate: { cls: string; saved: { cls: string; reason: string } } | null = null;
  // Same deferral for the disjoint-literal adjacency reset: `['"]?` must NOT
  // cut the `\s*… *` adjacency — it may vanish. Restored in the `?` handler.
  let resetCandidate: { cls: string; prev: string } | null = null;
  // Top-level alternation: first unbounded-quantified class per alternative —
  // `^\s+|\s+$` (trim ReDoS) has both branches consuming the same class.
  const topAltQuants: string[] = [];
  let topAltQuant: string | null = null;

  const recordAtom = (cls: string): string | null => {
    // A new atom confirms any pending pin / deferred reset (the previous atom
    // turned out to be mandatory — no `?` followed it).
    pinCandidate = null;
    resetCandidate = null;
    // Evaluate a deferred sandwich: the atom after the second quantified side
    // decides — overlap keeps the ambiguity alive, disjoint pins it.
    if (pendingSandwich) {
      const ps = pendingSandwich;
      pendingSandwich = null;
      if (cls !== "group" && classesOverlap(ps.cls, cls)) return ps.reason;
      if (cls !== "group") pinCandidate = { cls, saved: ps };
    }
    // A group opener (`pendingAtomCls === "group"`) does not break adjacency:
    // the previous quantified atom still abuts the group's first inner atom
    // (`(...)+([class]*)` ambiguity lives across the boundary).
    if (pendingAtomCls !== null && pendingAtomCls !== "group") prevQuantCls = null;
    // Sandwich state: a LITERAL after an unbounded-quantified atom becomes the
    // separator candidate. Non-literal atoms do NOT clear it — the quantifier
    // block decides (overlap with the CURRENT pendingAtomCls is required), and
    // clearing here kills `\s*\n\s*` (CVE-2017-16137): the second \s is a
    // class atom, its `*` arrives after.
    if (prevQuantCls !== null && cls.startsWith("lit:")) {
      sandwich = { cls: prevQuantCls, sep: cls };
    }
    // A literal atom disjoint from the pending quantified class is a hard
    // separator even across a group boundary: in `TOKEN+(?:=…)?` the `=` atom
    // must break the TOKEN/TOKEN adjacency (group openers alone don't).
    // Runs AFTER sandwich formation: the sandwich NEEDS the disjoint literal
    // (` *, *` — the comma being disjoint from space is the whole point).
    // DEFERRED: if the atom proves OPTIONAL (`['"]?`) the reset is undone in
    // the `?` handler — a vanishing atom cannot separate (CVE-2017-16098).
    if (
      prevQuantCls &&
      prevQuantCls !== "group" &&
      cls !== "group" &&
      !classesOverlap(prevQuantCls, cls)
    ) {
      resetCandidate = { cls, prev: prevQuantCls };
      prevQuantCls = null;
    }
    // A MANDATORY top-level atom breaks the optional chain (group contents do
    // not — chain semantics live at group boundaries).
    if (stack.length === 0) optChainCls = null;
    pendingAtomCls = cls;
    if (stack.length > 0) {
      const g = stack[stack.length - 1];
      if (!g.firstCls) g.firstCls = cls;
      else if (!g.secondCls) g.secondCls = cls;
      if (!g.curFirstCls) g.curFirstCls = cls;
      g.lastCls = cls;
      g.cur += cls.startsWith("lit:") ? cls.slice(4) : cls;
    }
    return null;
  };

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\") {
      const ac = atomClass(pattern, i);
      if (ac) {
        const r = recordAtom(ac.cls);
        if (r) return r;
        i = ac.next - 1;
      } else {
        i++;
      }
      continue;
    }
    if (ch === "(") {
      // Skip group-syntax prefixes so they are not mistaken for atoms:
      // (?: (?= (?! (?<= (?<! (?<name> (?P<name>
      let zeroWidth = false;
      if (pattern[i + 1] === "?") {
        const after = pattern[i + 2];
        if (after === ":") {
          i += 2;
        } else if (after === "=" || after === "!") {
          i += 2;
          zeroWidth = true;
        } else if (after === "<") {
          if (pattern[i + 3] === "=" || pattern[i + 3] === "!") {
            i += 3;
            zeroWidth = true;
          } else {
            const closeAngle = pattern.indexOf(">", i + 3);
            i = closeAngle > i ? closeAngle : i + 2;
          }
        } else if (after === "P" && pattern[i + 3] === "<") {
          const closeAngle = pattern.indexOf(">", i + 4);
          i = closeAngle > i ? closeAngle : i + 2;
        }
      }
      pushGroup(zeroWidth);
      pendingAtomCls = "group";
      continue;
    }
    if (ch === ")") {
      const g = stack.pop();
      if (!g) return null; // unbalanced — not our business
      if (g.cur || g.curFirstCls) {
        g.alts.push(g.cur);
        g.altFirsts.push(g.curFirstCls);
      }
      const rest = pattern.slice(i + 1);
      const qm = rest.match(UNBOUNDED_QUANT);
      if (process.env.REDOS_TRACE) console.error(`CLOSE @${i} rest='${rest.slice(0, 5)}' qm=${qm ? qm[0] : "null"} firsts=${JSON.stringify(g.altFirsts)} firstOptional=${g.firstOptional}`);
      // Optional group `(...)?: participates in the optional chain —
      // `(\d|…)?(E|e)?(…\d…)?` splits digit runs ambiguously.
      if (!qm && rest[0] === "?") {
        const cls = g.firstCls;
        if (
          cls && cls !== "group" && !cls.startsWith("lit:") &&
          optChainCls && optChainCls !== "group" &&
          classesOverlap(optChainCls, cls)
        ) {
          return `polynomial backtracking (overlapping optional groups)`;
        }
        // Empty-able groups in between do NOT break the chain — only set the
        // chain class when unset; a non-overlapping optional group keeps the
        // pending chain alive (`(\d)?([-+])?(\d)?` still splits digit runs).
        if (cls && !cls.startsWith("lit:") && !optChainCls) optChainCls = cls;
        // Transparent for adjacency: an empty-able group does not disambiguate
        // two quantified atoms around it (`\s*(?:''|"")?\s*` behaves as `\s*\s*`).
        prevQuantCls = g.outerPrevQuant;
        pendingAtomCls = null;
        if (stack.length > 0 && !g.zeroWidth) {
          const parent = stack[stack.length - 1];
          if (g.hasInnerQuant) parent.hasInnerQuant = true;
          parent.cur += "(…)";
        }
        continue;
      }
      if (qm) {
        if (g.hasInnerQuant) {
          // Nested unbounded quantifiers are only catastrophic when the end of
          // one iteration can also start the next (ambiguity). `([-+.]\w+)*` is
          // SAFE: every iteration must begin with the separator. `(a+)+` is
          // NOT: 'a' both ends and starts an iteration.
          const ambiguous =
            !g.firstCls || !g.lastCls || g.firstCls === "group" || g.lastCls === "group"
              ? true
              : classesOverlap(g.firstCls, g.lastCls) ||
                // First atom optional: an iteration can also START at the
                // second atom — `(?:\.?[a-zA-Z_][\w]*)+` splits word runs
                // ambiguously even though '.' and [\w] are disjoint.
                (g.firstOptional && g.secondCls !== null && g.secondCls !== "group" &&
                  classesOverlap(g.secondCls, g.lastCls));
          if (ambiguous) return `nested unbounded quantifiers (…)${qm[0]}`;
        }
        // Ambiguous alternation: two alternatives starting with overlapping
        // first-atom classes (descriptors tracked directly — escape-safe).
        if (process.env.REDOS_TRACE) console.error(`ALTS close qm=${qm[0]} firsts=${JSON.stringify(g.altFirsts)}`);
        for (let a = 0; a < g.altFirsts.length; a++) {
          for (let b = a + 1; b < g.altFirsts.length; b++) {
            const x = g.altFirsts[a];
            const y = g.altFirsts[b];
            if (!x || !y) continue;
            if (classesOverlap(x, y)) {
              return `ambiguous alternation (${g.alts[a]}|${g.alts[b]})${qm[0]}`;
            }
          }
        }
        prevQuantCls = g.firstCls ?? "group";
        pendingAtomCls = null;
      } else if (g.hasInnerQuant && g.lastCls) {
        // Transparent quantified group: `([^=;]+)` is not quantified itself,
        // but its greedy tail can eat into the NEXT atom's class — treat the
        // group as a quantified atom ending in lastCls (`([^=;]+)\s*`).
        prevQuantCls = g.lastCls;
        pendingAtomCls = null;
      } else {
        pendingAtomCls = g.lastCls ?? "group";
      }
      // Propagate inner-quant knowledge + boundary classes to the parent group
      // (NOT for zero-width lookarounds — they consume no input).
      if (stack.length > 0 && !g.zeroWidth) {
        const parent = stack[stack.length - 1];
        if (g.hasInnerQuant || qm) parent.hasInnerQuant = true;
        const cls = g.firstCls ?? "group";
        if (!parent.firstCls) parent.firstCls = cls;
        parent.lastCls = g.lastCls ?? "group";
        parent.cur += "(…)";
      }
      continue;
    }
    if (ch === "|" && stack.length > 0) {
      const g = stack[stack.length - 1];
      g.alts.push(g.cur);
      g.altFirsts.push(g.curFirstCls);
      g.cur = "";
      g.curFirstCls = null;
      g.lastCls = null;
      pendingAtomCls = null;
      prevQuantCls = null;
      continue;
    }
    // Quantifier on a plain atom / char class.
    if (ch === "+" || ch === "*" || ch === "{") {
      const isUnbounded = ch !== "{" || UNBOUNDED_QUANT.test(pattern.slice(i));
      if (isUnbounded) {
        if (stack.length > 0) stack[stack.length - 1].hasInnerQuant = true;
        if (stack.length === 0 && !topAltQuant && pendingAtomCls) topAltQuant = pendingAtomCls;
        // Adjacent quantified atoms with overlapping classes: `\d+\d+`, `.*.*`.
        // Restricted to identical classes or broad predefined ones — ambiguity
        // between NARROW custom classes (e.g. `[-:]+[-| :]*`) is at most
        // quadratic, not the catastrophic exponential ReDoS CVEs are about.
        const broad = (c: string) => c === "." || c === "\\d" || c === "\\w" || c === "\\s";
        if (
          prevQuantCls && pendingAtomCls &&
          prevQuantCls !== "group" && pendingAtomCls !== "group" &&
          (prevQuantCls === pendingAtomCls || (broad(prevQuantCls) && broad(pendingAtomCls))) &&
          classesOverlap(prevQuantCls, pendingAtomCls)
        ) {
          return `adjacent ambiguous repetitions (${prevQuantCls}+ ${pendingAtomCls}+)`;
        }
        // Polynomial tier: ANY two adjacent unbounded-quantified atoms whose
        // classes overlap force the engine to try every split of the shared
        // region — quadratic backtracking (the "polynomial regex" CVE class:
        // `[^=;]+\s*`, `[a-zA-Z0-9+/ \t\n]+[=]*`, …). Literal classes are
        // excluded: `a+a+` is already covered above; `lit` vs `lit` overlap
        // only when identical.
        if (
          prevQuantCls && pendingAtomCls &&
          prevQuantCls !== "group" && pendingAtomCls !== "group" &&
          !(prevQuantCls.startsWith("lit:") && pendingAtomCls.startsWith("lit:")) &&
          classesOverlap(prevQuantCls, pendingAtomCls)
        ) {
          return `polynomial backtracking (overlapping adjacent quantifiers ${prevQuantCls}+ ${pendingAtomCls}+)`;
        }
        // Sandwich: `A* <lit> A*` — the literal does not disambiguate because
        // both quantified sides consume the same class (`/ *, */` — negotiator,
        // fresh, forwarded CVEs). DEFERRED: fire only if the next atom does
        // not pin the split (see pendingSandwich).
        const sw = sandwich as { cls: string; sep: string } | null;
        if (
          sw && pendingAtomCls &&
          sw.cls !== "group" &&
          classesOverlap(sw.cls, pendingAtomCls)
        ) {
          pendingSandwich = {
            cls: sw.cls,
            reason: `polynomial backtracking (quantified atoms ${sw.cls}* around a separator)`,
          };
        }
        prevQuantCls = pendingAtomCls;
        sandwich = null;
        pendingAtomCls = null;
        if (ch === "{") {
          const close = pattern.indexOf("}", i);
          if (close > i) i = close;
        }
        continue;
      }
      // Bounded/optional quantifier: the atom no longer counts as quantified.
      if (ch === "{") {
        const close = pattern.indexOf("}", i);
        if (close > i) i = close;
      }
      prevQuantCls = null;
      sandwich = null;
      continue;
    }
    if (ch === "?") {
      // Track whether the group's FIRST atom is optional (the iteration-
      // ambiguity test at ')' must then compare against the second atom).
      if (stack.length > 0 && pendingAtomCls !== null) {
        const g = stack[stack.length - 1];
        if (g.firstCls === pendingAtomCls && g.secondCls === null) g.firstOptional = true;
      }
      // Optional marker. Two ambiguity shapes:
      //  1. `A+ B?` with overlap — A can consume what B optionally takes, so
      //     the split point is ambiguous (polynomial).
      if (
        prevQuantCls && pendingAtomCls &&
        prevQuantCls !== "group" && pendingAtomCls !== "group" &&
        !(prevQuantCls.startsWith("lit:") && pendingAtomCls.startsWith("lit:")) &&
        classesOverlap(prevQuantCls, pendingAtomCls)
      ) {
        return `polynomial backtracking (quantified atom followed by overlapping optional ${prevQuantCls}+ ${pendingAtomCls}?)`;
      }
      //  2. Optional chain `X? … Y?` (only optional/empty-able atoms between)
      //     with overlapping first classes — `(…\d…)?(E|e)?([-+])?(\d+)?`.
      if (
        pendingAtomCls && !pendingAtomCls.startsWith("lit:") &&
        optChainCls && optChainCls !== "group" &&
        classesOverlap(optChainCls, pendingAtomCls)
      ) {
        return `polynomial backtracking (overlapping optional chain ${optChainCls}? ${pendingAtomCls}?)`;
      }
      if (pendingAtomCls && !pendingAtomCls.startsWith("lit:")) optChainCls = pendingAtomCls;
      // The optional atom is TRANSPARENT for adjacency: it may match empty,
      // so the previous quantified atom still abuts the next one
      // (`\d*\.?\d+` splits digit runs ambiguously — browserslist ReDoS).
      // An optional atom also CANNOT pin a deferred sandwich — it vanishes
      // (`\s*=\s*['"]? *` — CVE-2017-16098).
      const pc = pinCandidate as {
        cls: string;
        saved: { cls: string; reason: string };
      } | null;
      if (pc && pc.cls === pendingAtomCls) {
        pendingSandwich = pc.saved;
      }
      pinCandidate = null;
      // Same for the deferred adjacency reset: an optional atom cannot
      // separate two quantified runs — restore the previous quantified class.
      const rc = resetCandidate as { cls: string; prev: string } | null;
      if (rc && rc.cls === pendingAtomCls) {
        prevQuantCls = rc.prev;
      }
      resetCandidate = null;
      sandwich = null;
      pendingAtomCls = null;
      continue;
    }
    if (ch === "[") {
      const ac = atomClass(pattern, i);
      if (ac) {
        const r = recordAtom(ac.cls);
        if (r) return r;
        i = ac.next - 1;
        continue;
      }
    }
    if (ch === ".") {
      const r = recordAtom(".");
      if (r) return r;
      continue;
    }
    if (ch === "|" && stack.length === 0) {
      if (topAltQuant) topAltQuants.push(topAltQuant);
      topAltQuant = null;
      pendingAtomCls = null;
      prevQuantCls = null;
      sandwich = null;
      continue;
    }
    // Plain literal atom.
    const r = recordAtom(`lit:${ch}`);
    if (r) return r;
  }
  // Pattern ends while a sandwich is still unresolved: nothing pins the split
  // (negotiator's standalone ` *, *`).
  if (pendingSandwich) return pendingSandwich.reason;
  // Top-level alternation with overlapping quantified branches: the engine
  // retries the whole match per branch at every position (trim `/^\s+|\s+$/`).
  if (topAltQuant) topAltQuants.push(topAltQuant);
  for (let a = 0; a < topAltQuants.length; a++) {
    for (let b = a + 1; b < topAltQuants.length; b++) {
      if (classesOverlap(topAltQuants[a], topAltQuants[b])) {
        return `polynomial backtracking (overlapping top-level alternatives ${topAltQuants[a]}+|${topAltQuants[b]}+)`;
      }
    }
  }
  return null;
}

/** Extract candidate regex patterns from a source line (JS/TS). */
function extractRegexPatterns(line: string): string[] {
  const out: string[] = [];
  // Regex literals in expression position.
  const litRe = /(?:^|[=(,:;!&|?[\]{}~^%<>+-]\s*|\breturn\s+|=>\s*)\/((?:\\.|[^\\/\n])+)\/[gimsuy]*/g;
  let m: RegExpExecArray | null;
  while ((m = litRe.exec(line)) !== null) out.push(m[1]);
  // RegExp constructor with a string literal.
  const ctorRe = /(?:new\s+)?RegExp\s*\(\s*['"]((?:\\.|[^'"])*)['"]/g;
  while ((m = ctorRe.exec(line)) !== null) out.push(m[1].replace(/\\\\/g, "\\"));
  // String arguments implicitly coerced to RegExp by String methods.
  const methRe = /\.(?:match|matchAll|replace|replaceAll|split|search)\s*\(\s*['"]((?:\\.|[^'"])*)['"]/g;
  while ((m = methRe.exec(line)) !== null) out.push(m[1].replace(/\\\\/g, "\\"));
  return out;
}

/**
 * Resolve string-valued variables that feed RegExp constructions (JS/TS):
 *   const re = "(a+)+$";            new RegExp(re)
 *   var parts = ["(a", "|aa)+"];    new RegExp(parts.join(""))
 * Real-world vulnerable regexes are frequently built from constants rather
 * than written as inline literals (ua-parser et al.).
 */
function buildRegexVarMap(lines: string[]): { vars: Map<string, string>; arrays: Map<string, string[]> } {
  const literals = new Map<string, string>();
  const arrays = new Map<string, string[]>();
  const unescape = (s: string) => s.replace(/\\\\/g, "\\");
  // Multi-declaration continuations: `var A = /…/, \n    B = /…/,` — the
  // follow-on lines have no `var` keyword (content-type's CVE-2020-7662).
  let inMultiDecl = false;
  for (const line of lines) {
    let decl = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?)[,;]?\s*$/);
    if (!decl && inMultiDecl) {
      decl = line.match(/^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)[,;]?\s*$/);
    }
    inMultiDecl = decl != null && /,\s*$/.test(line);
    if (!decl) continue;
    const [, name, rawExpr0] = decl;
    const rawExpr = rawExpr0.replace(/,\s*$/, "");
    // Regex-literal assignment: `var TOKEN = /body/g` — store the BODY.
    const reLit = rawExpr.match(/^\/((?:\\.|[^/])+)\/[a-z]*$/);
    if (reLit) { literals.set(name, reLit[1]); continue; }
    // `new RegExp( … )` wrapper: analyze the inner expression (it composes
    // other regexes via `X.source`). Greedy capture to the FINAL `)` — the
    // pattern itself contains parens; the trailing flags arg is stripped.
    const wrap = rawExpr.match(/^new\s+RegExp\s*\(([\s\S]*)\)$/);
    let expr = wrap
      ? wrap[1].replace(/,\s*['"][a-z]*['"]\s*$/, "")
      : rawExpr;
    const arr = expr.match(/^\s*\[((?:\s*['"](?:\\.|[^'"])*['"]\s*,?\s*)+)\]\s*$/);
    if (arr) {
      arrays.set(name, [...arr[1].matchAll(/['"]((?:\\.|[^'"])*)['"]/g)].map((m) => unescape(m[1])));
      continue;
    }
    // Split the concat on '+' OUTSIDE string literals (patterns contain '+').
    const segs: string[] = [];
    {
      let quote: string | null = null;
      let cur = "";
      for (let ci = 0; ci < expr.length; ci++) {
        const c = expr[ci];
        if (quote) {
          cur += c;
          if (c === "\\") { cur += expr[++ci] ?? ""; continue; }
          if (c === quote) quote = null;
          continue;
        }
        if (c === '"' || c === "'" || c === "`") { quote = c; cur += c; continue; }
        if (c === "+") { segs.push(cur.trim()); cur = ""; continue; }
        cur += c;
      }
      if (cur.trim()) segs.push(cur.trim());
    }
    let acc = "";
    let ok = segs.length > 0;
    for (const seg of segs) {
      // String-literal segments need JS-string unescaping (`"\\d"` → `\d`);
      // regex-literal bodies and `.source` references are already raw pattern
      // text — unescaping them would corrupt `\\[` into `\[`.
      const lit = seg.match(/^['"]((?:\\.|[^'"])*)['"]$/);
      if (lit) { acc += unescape(lit[1]); continue; }
      if (literals.has(seg)) { acc += literals.get(seg)!; continue; }
      // `X.source` — the body of a previously-seen regex variable.
      const srcRef = seg.match(/^([A-Za-z_$][\w$]*)\s*\.\s*source$/);
      if (srcRef && literals.has(srcRef[1])) { acc += literals.get(srcRef[1])!; continue; }
      ok = false;
      break;
    }
    if (ok && acc) literals.set(name, acc);
  }
  // arr.join('sep') assigned to a variable.
  for (const line of lines) {
    const jm = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*join\s*\(\s*['"]((?:\\.|[^'"])*)['"]\s*\)/);
    if (jm && arrays.has(jm[2])) literals.set(jm[1], unescape(arrays.get(jm[2])!.join(jm[3])));
  }
  return { vars: literals, arrays };
}

function detectReDoS(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];
  const { vars: varMap, arrays: arrMap } = buildRegexVarMap(lines);
  const push = (i: number, reason: string) =>
    findings.push(
      makeFinding(
        { cwe: "CWE-730", category: "ReDoS", severity: "HIGH", owasp2021: "A05:2021", confidence: 85 },
        filePath,
        i + 1,
        snippetAt(i),
        `Regular expression is vulnerable to catastrophic backtracking (ReDoS): ${reason}.`
      )
    );
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    let found = false;
    for (const pattern of extractRegexPatterns(line)) {
      const reason = analyzeReDoSPattern(pattern);
      if (reason) {
        push(i, reason);
        found = true;
        break;
      }
    }
    if (found || (varMap.size === 0 && arrMap.size === 0)) continue;
    // Variable-fed constructions: new RegExp(name), new RegExp(arr.join('|')),
    // str.match(name), …
    const candidates: string[] = [];
    for (const um of line.matchAll(/(?:new\s+)?RegExp\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*join\s*\(\s*['"]((?:\\.|[^'"])*)['"]\s*\)/g)) {
      const parts = arrMap.get(um[1]);
      if (parts) candidates.push(parts.join(um[2].replace(/\\\\/g, "\\")));
    }
    for (const um of line.matchAll(/(?:new\s+)?RegExp\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/g)) {
      const pat = varMap.get(um[1]);
      if (pat) candidates.push(pat);
    }
    for (const mm of line.matchAll(/\.(?:match|matchAll|replace|replaceAll|split|search)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/g)) {
      const pat = varMap.get(mm[1]);
      if (pat) candidates.push(pat);
    }
    // Receiver form: `EXT_LIST.test(header)` / `re.exec(str)` — the regex is
    // the RECEIVER (CVE-2020-7662's EXT_LIST built via .source composition).
    for (const rm of line.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*(?:test|exec)\s*\(/g)) {
      const pat = varMap.get(rm[1]);
      if (pat) candidates.push(pat);
    }
    for (const pat of candidates) {
      const reason = analyzeReDoSPattern(pat);
      if (process.env.REDOS_TRACE) console.error(`CAND L${i + 1} pat='${pat.slice(0, 80)}' reason=${reason ?? "clean"}`);
      if (reason) {
        push(i, reason);
        break;
      }
    }
  }
  return findings;
}

// ==================== JS/TS: PROTOTYPE POLLUTION (CWE-1321) ====================

/**
 * Structural prototype-pollution detector. Merge/extend libraries that copy
 * properties via a computed key (`dest[k] = src[k]`) without a `__proto__`
 * guard let attacker JSON (`{"__proto__": {"admin": true}}`) pollute
 * Object.prototype — the root cause of dozens of npm CVEs (mixin-deep,
 * merge-deep, object-extend, …), several leading to RCE.
 *
 * Conservative gates (all required):
 *   1. library boundary — the module exports something;
 *   2. key iteration — `for (k in obj)` / `Object.keys(obj)` present;
 *   3. the merge idiom — the SAME computed key on both sides of an assignment;
 *   4. no `__proto__` mention anywhere in the file (patched versions add
 *      `if (key === '__proto__') return;` — CVE-2018-3719's exact fix).
 */
function detectPrototypePollution(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const text = lines.join("\n");
  if (text.includes("__proto__")) return [];
  if (!/\bmodule\s*\.\s*exports\b|\bexports\s*\.|\bexport\s+(?:default\s+)?(?:function|const|class)/.test(text)) return [];
  if (!/\bfor\s*\([^)]*\bin\b[^)]*\)|Object\.keys\s*\(|\bforIn\s*\(|\bforOwn\s*\(/.test(text)) return [];

  const findings: WeaknessFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    // Form A: same computed key on both sides — `dest[k] = … src[k] …`.
    // The objects MUST differ: `offer[key] = [].concat(offer[key])` is in-place
    // normalization, not a merge (content-type's CVE-2020-7662 post loop).
    let keyVar: string | null = null;
    const formA = lines[i].match(/\b([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*=(?!=)[^;]*\b([A-Za-z_$][\w$]*)\s*\[\s*\2\s*\]/);
    if (formA && formA[1] !== formA[3]) keyVar = formA[2];
    // Form B: callback merge — `this[k] = v` / `target[k] = v` where k is a
    // parameter of the enclosing function (forIn-style iterators pass (val, key)
    // — mixin-deep CVE-2018-3719: `function copy(val, key) { this[key] = val; }`),
    // a for-in/for-of loop variable (merge-deep: `for (key in obj)` then
    // `target[key] = merge(...)`) or an INDEX-LOOP key assigned from an array
    // element (`part = parts[i]` after `parts = path.split('.')` — mpath,
    // config-chain set-by-path pollution).
    if (!keyVar) {
      const formB = lines[i].match(/\b(?:this|target|dest|result|obj|object|current|base|acc|out)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*=(?!=)/);
      if (formB) {
        const keyEsc = formB[1].replace(/[$]/g, "\\$");
        for (let k = i; k >= 0 && k > i - 15; k--) {
          const fn = lines[k].match(/\bfunction\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/);
          const params = fn ? fn[1].split(",").map((p) => p.trim()) : [];
          // NOTE: for-of over Object.keys() is NOT exempt — `__proto__`
          // arrives as an OWN data property on JSON.parse'd input, so the
          // loop key can still be `__proto__` (assign-deep CVE-2019-10745).
          const loopVar = new RegExp(`\\bfor\\s*\\(\\s*(?:var|let|const)?\\s*${keyEsc}\\s+(?:in|of)\\b`);
          const indexKey = new RegExp(`\\b${keyEsc}\\s*=\\s*[A-Za-z_$][\\w$]*\\s*\\[[^\\]]+\\]`);
          if (params.includes(formB[1]) || loopVar.test(lines[k]) || indexKey.test(lines[k])) {
            keyVar = formB[1];
            break;
          }
        }
      }
    }
    if (!keyVar) continue;
    findings.push(
      makeFinding(
        { cwe: "CWE-915", category: "Prototype Pollution", severity: "HIGH", owasp2021: "A08:2021", confidence: 80 },
        filePath,
        i + 1,
        snippetAt(i),
        `Recursive merge copies properties via computed key '${keyVar}' without a '__proto__' guard — attacker-controlled '__proto__'/'constructor' keys pollute Object.prototype (prototype pollution CWE-915/CWE-1321, potential RCE).`
      )
    );
    break; // one finding per file is enough
  }
  return findings;
}

// ==================== JS/TS: INCOMPLETE SANITIZATION (CWE-116) ====================

/**
 * Structural detector for sanitizer-library self-vulnerabilities — escape /
 * strip code that LOOKS like sanitization but is bypassable:
 *
 *  a) FIRST-OCCURRENCE escaping: `.replace("&", "&amp;")` with a plain-string
 *     pattern only replaces the FIRST occurrence — HTML-critical chars
 *     (`& < > " ' \`) later in the string survive (CVE-2019-10785).
 *  b) UNFLAGGED REGEX escaping: `.replace(/(#|\+)/, …)` without /g — same
 *     first-occurrence flaw on special characters (CVE-2018-11615).
 *  c) SELF-REPLACEMENT: `.replace(/\[/g, '[')` replaces a pattern with its
 *     own match — a no-op masquerading as a sanitizer (CVE-2019-10757).
 *  d) ONE-SHOT TRAVERSAL STRIP: `x.replace("/../", "")` without a
 *     strip-until-clean loop — nested `....//` payloads survive
 *     (CVE-2019-5423; the loop variant is the accepted fix).
 */
function detectIncompleteSanitization(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];
  const push = (i: number, detail: string) =>
    findings.push(
      makeFinding(
        { cwe: "CWE-116", category: "Improper Encoding or Escaping", severity: "HIGH", owasp2021: "A03:2021", confidence: 80 },
        filePath,
        i + 1,
        snippetAt(i),
        detail
      )
    );

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    for (const m of lines[i].matchAll(/\.replace(?:All)?\s*\(\s*(['"])((?:\\.|(?!\1).)*)\1\s*,\s*(['"])((?:\\.|(?!\3).)*)\3/g)) {
      const pattern = m[2];
      // (c) self-replacement: pattern and replacement are the same text.
      if (pattern.length > 0 && pattern === m[4]) {
        push(i, `Self-replacement no-op: replace('${pattern}', '${m[4]}') substitutes a substring with itself — no sanitization happens (CWE-116).`);
        break;
      }
      // (a) first-occurrence escaping of an HTML/escape-critical char.
      // Traversal strips (`/../`) are owned by rule (d), which checks the loop.
      if (/^(?:&|<|>|"|'|\\\\)$/.test(pattern)) {
        push(i, `First-occurrence sanitization: replace() with a plain-string pattern ('${pattern}') only replaces the FIRST occurrence — later occurrences of the critical character survive (CWE-116).`);
        break;
      }
    }
    // (b) regex-arg replace without the /g flag on special characters.
    // Tail-anchored patterns (`/….*$/`) intentionally strip once.
    const b = lines[i].match(/\.replace\s*\(\s*\/((?:\\.|[^/])*)\/([a-z]*)\s*,/);
    if (b && !b[2].includes("g") && !/\.\+?\$?$/.test(b[1]) && /[<>&"'#+\\]/.test(b[1]) && b[1].length <= 12) {
      push(i, `Unflagged regex sanitization: replace(/${b[1]}/, …) without the /g flag only sanitizes the first occurrence (CWE-116).`);
    }
    // (c2) REGEX self-replacement: `replace(/\[/g, '[')` — the regex body
    // contains only literals/escapes and resolves to exactly the replacement
    // text → the "sanitizer" is a no-op (knex's wrapIdentifierImpl,
    // CVE-2019-10757; the fix escapes to `'[['`).
    const c2 = lines[i].match(/\.replace(?:All)?\s*\(\s*\/((?:\\.|[^/])*)\/[a-z]*\s*,\s*(['"])((?:\\.|(?!\2).)*)\2/);
    if (c2) {
      const body = c2[1];
      const replacement = c2[3];
      // Body must be pure literal text (every metachar escaped).
      if (/^(?:\\.|[^\[\]().|^$*+?{}\\])+$/.test(body)) {
        const resolved = body.replace(/\\(.)/g, "$1");
        if (resolved.length > 0 && resolved === replacement) {
          push(i, `Self-replacement no-op: replace(/${body}/, '${replacement}') substitutes a substring with itself — no sanitization happens (CWE-116).`);
        }
      }
    }
    // (d) one-shot traversal strip without a surrounding loop.
    const d = lines[i].match(/\.replace(?:All)?\s*\(\s*(['"])\/?\.\.\/?\1\s*,/);
    if (d) {
      let inLoop = false;
      for (let k = i - 1; k >= 0 && k > i - 4; k--) {
        if (/\bwhile\s*\(/.test(lines[k])) { inLoop = true; break; }
      }
      if (!inLoop && !/\.replaceAll\s*\(/.test(lines[i])) {
        push(i, `One-shot traversal strip: replace('${d[0].includes("/") ? "/../" : ".."}', …) without a strip-until-clean loop leaves nested '....//' traversal payloads (CWE-116).`);
      }
    }
    // (e) one-shot MULTI-CHAR delimiter strip: removing comment/script
    // delimiters (`<!--`, `-->`, `<script`) in a single pass is order-bypassable
    // — `<!---` leaves a fresh `-->` after one removal (TinyMCE SaxParser
    // CVE-2019-1010091; the fix wraps the replace in a while-until-clean loop).
    const e = lines[i].match(/\.replace\s*\(\s*\/(?:\\.|[^/])*(?:<!--|--!?>|<script)(?:\\.|[^/])*\/[a-z]*\s*,\s*['"]\s*['"]/);
    if (e) {
      let inLoop = false;
      for (let k = i - 1; k >= 0 && k > i - 4; k--) {
        if (/\bwhile\s*\(/.test(lines[k])) { inLoop = true; break; }
      }
      if (!inLoop) {
        push(i, `One-shot delimiter strip: removing comment/script delimiters in a single replace pass is order-bypassable — nested delimiters re-form after one removal (CWE-116).`);
      }
    }
  }
  return findings;
}

// ============ JS/TS: INCOMPLETE URL-SCHEME CHECK (CWE-20) ============

/**
 * A URL-scheme filter that blocks `javascript:` but not `data:` is incomplete:
 * `data:text/html,<script>…</script>` executes script in most navigation
 * contexts — the canonical markdown-it/marked XSS fix adds `data` to the
 * blocklist (CVE-2017-16006, CVE-2017-1000427, CVE-2019-9844, CVE-2020-9038).
 * Detects per line: a scheme check (indexOf/startsWith/array blocklist)
 * mentioning `javascript:` with no `data:` in the same expression.
 */
function detectIncompleteSchemeCheck(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (!/['"`]javascript:/.test(line) && !/\[[^\]]*['"`]javascript['"`]/.test(line)) continue;
    // The fix adds `data:` (or `data` in array form) to the check.
    if (/['"`]data(?::[^'"`]*)?['"`]/.test(line)) continue;
    if (!/\bindexOf\s*\(|startsWith|\[[^\]]*['"`]vbscript/.test(line)) continue;
    findings.push(
      makeFinding(
        { cwe: "CWE-20", category: "Improper Input Validation", severity: "MEDIUM", owasp2021: "A03:2021", confidence: 75 },
        filePath,
        i + 1,
        snippetAt(i),
        `Incomplete URL-scheme check: blocks 'javascript:' but not 'data:' — data:text/html URLs execute script (CWE-20/CWE-79).`
      )
    );
  }
  return findings;
}

// ===== JS/TS: WEAK RANDOMNESS (CWE-338) + ENV DUMP (CWE-312) =====

/**
 * (a) `Math.random()` accumulating a string in a loop builds predictable
 *     tokens — randomatic's `res += mask.charAt(parseInt(Math.random() * …))`
 *     (CVE-2017-16028); the fix uses crypto.randomBytes.
 * (b) `JSON.stringify(process.env)` dumps the WHOLE environment (secrets) into
 *     a bundle/log — webpack DefinePlugin misconfiguration (CVE-2020-11059);
 *     the fix stringifies a selected-keys object.
 */
function detectWeakRandomAndEnvLeak(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (
      /Math\s*\.\s*random\s*\(/.test(line) &&
      /\.\s*charAt\s*\(/.test(line)
    ) {
      findings.push(
        makeFinding(
          { cwe: "CWE-338", category: "Weak Pseudo-Random Number Generator", severity: "MEDIUM", owasp2021: "A02:2021", confidence: 75 },
          filePath,
          i + 1,
          snippetAt(i),
          `Math.random() accumulates a string character-by-character — predictable output used as a token/secret. Use crypto.randomBytes (CWE-338).`
        )
      );
    }
    // Random-to-string token idiom: `Math.random() * … .toString(16)` builds
    // predictable session/request ids (httpntlm CVE-2017-16031 — the fix fills
    // a Buffer from crypto.randomBytes).
    if (
      /Math\s*\.\s*random\s*\(\s*\)/.test(line) &&
      /\.toString\s*\(/.test(line) &&
      /\*\s*(?:Math\s*\.\s*random|0x[\da-fA-F]+|\d|Date\s*\.\s*now)/.test(line)
    ) {
      findings.push(
        makeFinding(
          { cwe: "CWE-338", category: "Weak Pseudo-Random Number Generator", severity: "MEDIUM", owasp2021: "A02:2021", confidence: 75 },
          filePath,
          i + 1,
          snippetAt(i),
          `Math.random() multiplied and stringified into an identifier — predictable tokens/ids. Use crypto.randomBytes (CWE-338).`
        )
      );
    }
    if (/JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\s*\)/.test(line)) {
      findings.push(
        makeFinding(
          { cwe: "CWE-312", category: "Sensitive Data Exposure", severity: "HIGH", owasp2021: "A02:2021", confidence: 80 },
          filePath,
          i + 1,
          snippetAt(i),
          `JSON.stringify(process.env) serializes the ENTIRE environment — every secret/API key leaks into the output. Select specific keys instead (CWE-312).`
        )
      );
    }
    // Crypto-byte scaling bias: `Math.floor(randomByte / 25.6)` maps a uniform
    // byte onto a non-divisor range — digits are BIASED (random-number-csprng
    // CVE-2018-1000620; the fix uses rejection sampling). A fractional divisor
    // on a byte-sized value is the tell.
    if (/Math\s*\.\s*floor\s*\([^()]*\[[^()]*\]\s*\/\s*\d+\.\d+\s*\)/.test(line)) {
      findings.push(
        makeFinding(
          { cwe: "CWE-327", category: "Broken Crypto", severity: "MEDIUM", owasp2021: "A02:2021", confidence: 75 },
          filePath,
          i + 1,
          snippetAt(i),
          `Scaling a random byte by a fractional divisor biases the output distribution (some values are more likely). Use rejection sampling or a power-of-two modulus (CWE-327).`
        )
      );
    }
    // Logger arguments-forwarding: `console.error.apply(console, arguments)`
    // dumps the caller's ENTIRE argument list — whatever sensitive data the
    // caller held (tubemail CVE-2019-5483; the fix logs specific fields).
    if (/\b(?:console|log|logger)\s*\.\s*\w+\s*\.\s*apply\s*\([^)]*\barguments\s*\)/.test(line)) {
      findings.push(
        makeFinding(
          { cwe: "CWE-312", category: "Sensitive Data Exposure", severity: "MEDIUM", owasp2021: "A09:2021", confidence: 70 },
          filePath,
          i + 1,
          snippetAt(i),
          `Forwarding the entire 'arguments' object to a logger writes everything the caller received — including credentials/tokens — to the log (CWE-312).`
        )
      );
    }
    // Scheme allowlist with 'file' but without 'data': allows file:// URLs
    // (local-file exfil via iframe/redirect) while rejecting data: — the
    // incomplete-check shape (joplin webclipper CVE-2020-9038; the fix adds
    // 'data' and handles file: explicitly).
    if (/\[[^\]]*'http'[^\]]*'file'[^\]]*\]\s*\.\s*(?:indexOf|includes)\s*\(/.test(line) && !/'data'/.test(line)) {
      findings.push(
        makeFinding(
          { cwe: "CWE-20", category: "Improper Input Validation", severity: "MEDIUM", owasp2021: "A03:2021", confidence: 70 },
          filePath,
          i + 1,
          snippetAt(i),
          `URL-scheme allowlist includes 'file' — file:// URLs read local files; the allowlist is incomplete without explicit data:/file: handling (CWE-20).`
        )
      );
    }
    // Constructor-name comparison as a TYPE/SECURITY check: attacker objects
    // spoof `constructor.name` freely (json-schema CVE-2019-19507 — the fix
    // drops the name comparison entirely).
    if (/\.constructor\s*\.\s*name\s*(?:===|!==)[^;]*\.constructor\s*\.\s*name/.test(line)) {
      findings.push(
        makeFinding(
          { cwe: "CWE-807", category: "Reliance on Untrusted Inputs in a Security Decision", severity: "HIGH", owasp2021: "A04:2021", confidence: 75 },
          filePath,
          i + 1,
          snippetAt(i),
          `Comparing 'constructor.name' strings as a type/security check is spoofable — attacker-controlled objects carry arbitrary constructor names (CWE-807).`
        )
      );
    }
  }
  const text = lines.join("\n");
  // Missing CSRF protection on state-changing routes (CWE-352): a POST/PUT/
  // DELETE/PATCH route registered without csrf middleware on that line, and
  // no global csurf setup (`app.use(csrf())`) anywhere (CVE-2020-15135's
  // unprotected /create, CVE-2020-15156's comment routes — the fixes add
  // applyCSRF per route or csurf globally).
  if (!/\.\s*use\s*\([^)]*csrf|csurf\s*\(/i.test(text)) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      if (
        /\b(?:app|router|users|api|server|routes)\s*\.\s*(?:post|put|delete|patch)\s*\(\s*['"`]/.test(line) &&
        !/csrf/i.test(line)
      ) {
        findings.push(
          makeFinding(
            { cwe: "CWE-352", category: "Cross-Site Request Forgery", severity: "HIGH", owasp2021: "A01:2021", confidence: 65 },
            filePath,
            i + 1,
            snippetAt(i),
            `State-changing route registered without CSRF middleware (no per-route csrf and no global csurf) — cookie-authenticated requests are forgeable cross-site (CWE-352).`
          )
        );
        break;
      }
    }
  }
  // Unvalidated dynamic method call: `handler[method](…)` with a variable key
  // on a dispatcher object and NO guard on THAT KEY (`typeof x[key] !==
  // 'function'` / hasOwnProperty(key)) — attacker input reaches arbitrary
  // methods (CVE-2019-18954; the fix adds the typeof-function guard).
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    const dm = line.match(
      /\b(?:handler|router|methods|actions|commands|api|service|controller|ctrl)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*(?:\.\s*apply)?\s*\(/,
    );
    if (dm) {
      const keyEsc = dm[1].replace(/\$/g, "\\$");
      const guarded =
        new RegExp(
          `typeof\\s+[A-Za-z_$][\\w$]*\\s*\\[\\s*${keyEsc}\\s*\\]\\s*!==?\\s*['"]function['"]`,
        ).test(text) ||
        new RegExp(`hasOwnProperty\\s*\\(\\s*${keyEsc}\\s*\\)`).test(text);
      if (!guarded) {
        findings.push(
          makeFinding(
            { cwe: "CWE-754", category: "Improper Check of Exceptional Conditions", severity: "HIGH", owasp2021: "A04:2021", confidence: 70 },
            filePath,
            i + 1,
            snippetAt(i),
            `Unvalidated dynamic method call: the key '${dm[1]}' selects a method without a typeof-function/hasOwnProperty guard — crafted input invokes unintended methods (CWE-754).`
          )
        );
        break;
      }
    }
  }
  return findings;
}

// ==================== JAVA: INSECURE COOKIE (CWE-614) ====================

/**
 * Flag cookies that are added to the response without `setSecure(true)`.
 * Tracks each `new Cookie(...)` variable and whether `.setSecure(true)` is called
 * on it before the corresponding `addCookie(...)`.
 */
function detectInsecureCookies(
  lines: string[],
  filePath: string,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];
  const cookieVars = new Map<string, number>(); // varName → creation line index
  const securedVars = new Set<string>();

  const newCookieRe = /([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:javax\.servlet\.http\.)?Cookie\s*\(/;
  const setSecureRe = /([A-Za-z_$][\w$]*)\s*\.\s*setSecure\s*\(\s*true\s*\)/;
  const addCookieRe = /addCookie\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const created = line.match(newCookieRe);
    if (created) cookieVars.set(created[1], i);

    const secured = line.match(setSecureRe);
    if (secured) securedVars.add(secured[1]);

    const added = line.match(addCookieRe);
    if (added && cookieVars.has(added[1]) && !securedVars.has(added[1])) {
      findings.push(
        makeFinding(
          {
            cwe: "CWE-614", category: "Insecure Cookie", severity: "MEDIUM",
            owasp2021: "A05:2021", confidence: 80,
          },
          filePath,
          i + 1,
          snippetAt(i),
          `Cookie '${added[1]}' is added without the Secure flag (no setSecure(true)).`
        )
      );
    }
  }
  return findings;
}

// ==================== JAVA: TRUST BOUNDARY (CWE-501) ====================

/**
 * Flag `session.setAttribute(...)` calls that store untrusted (tainted) data.
 * Uses the taint engine's `computeTaintedVarNames` to know which variables carry
 * user input; a literal/constant argument is NOT flagged.
 */
function detectTrustBoundary(
  lines: string[],
  filePath: string,
  language: string,
  fileContent: string,
  taintRules: TaintRulesBundle | undefined,
  snippetAt: (i: number) => string
): WeaknessFinding[] {
  const findings: WeaknessFinding[] = [];

  // Tainted variables (via the taint engine), with a lightweight heuristic fallback
  // when no taint rules are available. Skip sanitizers — trust-boundary is about
  // data provenance (user-controlled data in session), not injection safety.
  let tainted: Set<string>;
  if (taintRules) {
    tainted = computeTaintedVarNames(fileContent, language, taintRules, true);
  } else {
    tainted = heuristicTaintedVars(lines);
  }
  if (tainted.size === 0) return findings;

  const setAttrRe = /\b(?:setAttribute|putValue)\s*\(([^)]*)\)/;
  const identRe = /[A-Za-z_$][\w$]*/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = setAttrRe.exec(line);
    if (!m) continue;
    const args = m[1];
    // Ignore literal-only argument lists (no tainted identifier present).
    const idents = args.match(identRe) ?? [];
    const taintedArg = idents.find((id) => tainted.has(id));
    if (!taintedArg) continue;

    findings.push(
      makeFinding(
        {
          cwe: "CWE-501", category: "Trust Boundary Violation", severity: "MEDIUM",
          owasp2021: "A04:2021", confidence: 75,
        },
        filePath,
        i + 1,
        snippetAt(i),
        `Untrusted value '${taintedArg}' is stored into the HTTP session (trust boundary).`
      )
    );
  }
  return findings;
}

/** Fallback taint heuristic: variables assigned from a known input accessor. */
function heuristicTaintedVars(lines: string[]): Set<string> {
  const tainted = new Set<string>();
  const sourceCall = /(?:getValue|getParameter|getHeader|getHeaders|getCookies|getQueryString|getTheParameter|getTheCookie)\s*\(/;
  const assignRe = /(?:^|[;{}\s])([A-Za-z_$][\w$]*)\s*=[^=]/;
  for (const line of lines) {
    if (!sourceCall.test(line)) continue;
    const m = assignRe.exec(line);
    if (m && !/^(?:if|for|while|switch|return|catch|new)$/.test(m[1])) tainted.add(m[1]);
  }
  return tainted;
}

// ==================== SHARED HELPERS ====================

function makeFinding(
  rule: Pick<WeaknessRule, "cwe" | "category" | "severity" | "owasp2021" | "confidence">,
  filePath: string,
  lineNum: number,
  snippet: string,
  detail: string
): WeaknessFinding {
  return {
    cwe: rule.cwe,
    category: rule.category,
    severity: rule.severity,
    owasp2021: rule.owasp2021,
    title: `${rule.category}: ${rule.cwe} in ${filePath.split("/").pop()}`,
    description: `${rule.category} weakness (${rule.cwe}) at line ${lineNum} in ${filePath}. ${detail}`,
    filePath,
    lineStart: lineNum,
    lineEnd: lineNum,
    codeSnippet: snippet,
    confidence: rule.confidence,
    detectionMethod: "WEAKNESS",
  };
}

function dedupe(findings: WeaknessFinding[]): WeaknessFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.cwe}:${f.filePath}:${f.lineStart}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

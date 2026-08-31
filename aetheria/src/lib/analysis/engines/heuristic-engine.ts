/**
 * Heuristic Engine
 * Lightweight pattern checks that don't fit the taint/secret/IaC models:
 *  - ReDoS (CWE-1333): regex literals with nested quantifiers or ambiguous
 *    alternation under repetition — exponential backtracking risk.
 *  - CWE-200: sensitive identifiers (password/token/secret/...) passed to
 *    logging calls.
 *
 * Conservative on purpose: findings carry medium confidence and go through
 * the standard FP detector + AI triage phases afterwards.
 */

export interface HeuristicFinding {
  cwe: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  owasp2021: string;
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  confidence: number;
  detectionMethod: "HEURISTIC";
}

// ==================== ReDoS (CWE-1333) ====================

// Group whose body applies + or * to an inner expression and is itself
// quantified: (a+)+, (\w*)+, (x+\w*)* ... classic exponential backtracking.
const NESTED_QUANTIFIER = /\((?:[^()\\]|\\.)*(?:\w|\.|\[[^\]]*\])[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,?\d*\})/;

function hasAmbiguousAlternation(pattern: string): boolean {
  // (a|aa)+, (ab|a)* — alternatives sharing a prefix under a quantifier.
  const m = pattern.match(/\(([^()]*\|[^()]*)\)\s*(?:[+*]|\{\d+,?\d*\})/);
  if (!m) return false;
  const alts = m[1].split("|").map((a) => a.replace(/\\./g, "x"));
  for (let i = 0; i < alts.length; i++) {
    for (let j = 0; j < alts.length; j++) {
      if (i !== j && alts[i] && alts[j].startsWith(alts[i])) return true;
    }
  }
  return false;
}

interface RegexCandidate {
  pattern: string;
  index: number;
}

function extractRegexCandidates(content: string): RegexCandidate[] {
  const out: RegexCandidate[] = [];
  // new RegExp("...") / new RegExp('...')
  const ctorRe = /new\s+RegExp\(\s*(["'])((?:\\.|(?!\1).)*)\1/g;
  let m: RegExpExecArray | null;
  while ((m = ctorRe.exec(content)) !== null) {
    out.push({ pattern: m[2].replace(/\\\\/g, "\\"), index: m.index });
  }
  // Regex literals: /.../flags preceded by an operator/keyword context
  const litRe = /(?:^|[=(:,!&|?;{}\s]|return\s|=>)\s*\/((?:\\\/|\\.|[^/\n\\])+)\/[gimsuy]*/gm;
  while ((m = litRe.exec(content)) !== null) {
    out.push({ pattern: m[1], index: m.index });
  }
  return out;
}

// ==================== Sensitive logging (CWE-200) ====================

const LOG_CALL = /\b(?:console\.(?:log|info|warn|error|debug)|logger\.(?:log|info|warn|error|debug)|log\.(?:info|warn|error|debug))\s*\(([^)]*)\)/;
const SENSITIVE_IDENT = /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|ssn|cvv|card[_-]?number)\b/i;

// ==================== MAIN ====================

export function runHeuristicChecks(content: string, filePath: string): HeuristicFinding[] {
  const findings: HeuristicFinding[] = [];
  if (content.length > 500_000 || filePath.endsWith(".min.js")) return findings;

  const lineOf = (idx: number) => content.slice(0, idx).split("\n").length;
  const snippetAt = (line: number) =>
    content.split("\n")[line - 1]?.trim().slice(0, 200) ?? "";

  const seenRedosLine = new Set<number>();
  for (const cand of extractRegexCandidates(content)) {
    const nested = NESTED_QUANTIFIER.test(cand.pattern);
    const ambiguous = hasAmbiguousAlternation(cand.pattern);
    if (!nested && !ambiguous) continue;
    const line = lineOf(cand.index);
    if (seenRedosLine.has(line)) continue;
    seenRedosLine.add(line);
    findings.push({
      cwe: "CWE-1333",
      category: "redos",
      severity: "HIGH",
      owasp2021: "A05:2021",
      title: `ReDoS: regex con backtracking exponencial en ${filePath.split("/").pop()}`,
      description:
        `La expresión regular /${cand.pattern.slice(0, 120)}/ contiene ${nested ? "cuantificadores anidados" : "alternativas ambiguas bajo repetición"}, ` +
        "lo que permite entradas que disparan backtracking exponencial (denegación de servicio). " +
        "Reescribe el patrón para que cada carácter consumido sea inequívoco o usa una librería lineal (RE2).",
      filePath,
      lineStart: line,
      lineEnd: line,
      codeSnippet: snippetAt(line),
      confidence: 70,
      detectionMethod: "HEURISTIC",
    });
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    const m = line.match(LOG_CALL);
    if (!m || !SENSITIVE_IDENT.test(m[1])) continue;
    findings.push({
      cwe: "CWE-200",
      category: "info-exposure",
      severity: "MEDIUM",
      owasp2021: "A09:2021",
      title: `Datos sensibles en logging en ${filePath.split("/").pop()}`,
      description:
        "Se registran en logs identificadores que parecen contener credenciales o datos sensibles " +
        "(password/token/secret/key). Los logs suelen tener menor protección que el almacenamiento primario " +
        "y agregadores externos pueden exfiltrarlos. Enmascara el valor antes de registrarlo.",
      filePath,
      lineStart: i + 1,
      lineEnd: i + 1,
      codeSnippet: trimmed.slice(0, 200),
      confidence: 72,
      detectionMethod: "HEURISTIC",
    });
  }

  return findings;
}

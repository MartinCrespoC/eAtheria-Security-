/**
 * FP Knowledge System — NIST Juliet adapter (benchmark cases).
 *
 * The Juliet Test Suite (SAMATE/NIST) ships ~64k Java test cases named like
 * `CWE89_SQL_Injection__<flow>_01.java`, each containing a `bad()` method (a
 * REAL vulnerability → expected TP) and `goodN()` methods (the same construct
 * properly mitigated → expected FP). We parse these into labeled benchmark
 * cases that the harness (Fase 5) scores our detector against.
 *
 * Juliet is a licensed NIST download with no stable git mirror, so `fetch()`
 * does NOT download it — drop the extracted `Java/` tree into `vendor/fp/juliet`
 * and re-run. If absent, this adapter simply yields zero cases (non-fatal).
 * It produces NO FP patterns and NO CWE knowledge.
 */
import * as fs from "fs";
import * as path from "path";
import { VENDOR_ROOT } from "../orchestrator";
import type { BenchmarkCaseInput, FpSourceAdapter, NormalizedFpPattern } from "../types";

const JULIET_DIR = path.join(VENDOR_ROOT, "juliet");
const MAX_SNIPPET = 4000;

/** Map a Juliet filename description to an internal category key. */
function categorize(desc: string): string {
  const d = desc.toLowerCase();
  if (d.includes("sql_injection")) return "sqli";
  if (d.includes("xss") || d.includes("cross_site_scripting")) return "xss";
  if (d.includes("command_injection") || d.includes("os_command")) return "command-injection";
  if (d.includes("path_traversal") || d.includes("relative_path")) return "path-traversal";
  if (d.includes("ldap_injection")) return "ldap-injection";
  if (d.includes("xpath_injection")) return "xpath-injection";
  if (d.includes("hardcoded") || d.includes("hard_coded")) return "secret";
  if (d.includes("weak") || d.includes("broken") || d.includes("crypto") || d.includes("hash")) return "crypto";
  return desc.replace(/_/g, "-").toLowerCase();
}

/**
 * Extract a method body by brace counting from the first match of `headerRe`.
 * Returns the bounded source slice, or null if not found.
 */
function extractMethodBody(source: string, headerRe: RegExp): string | null {
  const m = headerRe.exec(source);
  if (!m) return null;
  const start = source.indexOf("{", m.index);
  if (start === -1) return null;
  let depth = 0;
  for (let i = start; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return source.slice(m.index, Math.min(i + 1, m.index + MAX_SNIPPET));
    }
    if (i - m.index > MAX_SNIPPET) break;
  }
  return source.slice(m.index, m.index + MAX_SNIPPET);
}

export class JulietAdapter implements FpSourceAdapter {
  id = "juliet";
  name = "NIST Juliet (benchmark cases)";

  async fetch(): Promise<void> {
    // No automated download (licensed NIST dataset). Ensure the dir exists so
    // users can drop the extracted Java tree in; absent → zero cases.
    fs.mkdirSync(JULIET_DIR, { recursive: true });
  }

  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    return [];
  }

  async parseBenchmarkCases(): Promise<BenchmarkCaseInput[]> {
    if (!fs.existsSync(JULIET_DIR)) return [];

    const cases: BenchmarkCaseInput[] = [];
    const stack: string[] = [JULIET_DIR];
    const fileRe = /CWE(\d+)_([A-Za-z0-9_]+?)__/;

    while (stack.length) {
      const dir = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          stack.push(full);
          continue;
        }
        if (!ent.name.endsWith(".java")) continue;
        const fm = fileRe.exec(ent.name);
        if (!fm) continue;

        const cweId = `CWE-${fm[1]}`;
        const category = categorize(fm[2]);

        let source: string;
        try {
          source = fs.readFileSync(full, "utf8");
        } catch {
          continue;
        }

        // bad() → real vulnerability (expected TP).
        const bad = extractMethodBody(source, /\b(?:public\s+)?void\s+bad\s*\(/);
        if (bad) {
          cases.push({ cweId, category, expected: "TP", snippet: bad, language: "java" });
        }
        // Mitigated variant (expected FP). Juliet 1.3 files come in two
        // styles: `good1()` (older) or a delegate `good()` that only calls
        // goodG2B()/goodB2G(). In the delegate style the real mitigated code
        // lives in `goodB2G()` (bad source → GOOD sink) when present, else in
        // `goodG2B()` (GOOD source → bad sink).
        const good =
          extractMethodBody(source, /\b(?:private\s+)?void\s+good1\s*\(/) ??
          extractMethodBody(source, /\b(?:private\s+)?void\s+goodB2G\s*\(/) ??
          extractMethodBody(source, /\b(?:private\s+)?void\s+goodG2B\s*\(/) ??
          extractMethodBody(source, /\b(?:private\s+)?void\s+good\s*\(/);
        if (good) {
          cases.push({ cweId, category, expected: "FP", snippet: good, language: "java" });
        }
      }
    }

    return cases;
  }
}

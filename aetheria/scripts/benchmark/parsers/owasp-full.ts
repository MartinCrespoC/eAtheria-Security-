/**
 * OWASP Benchmark — "lite" parser (no Java/Maven required).
 *
 * Reads the official ground-truth labels (`expectedresults-1.2.csv`, format:
 * `test name, category, real vulnerability, cwe`) and the matching
 * `BenchmarkTest#####.java` source for each of the ~2,740 cases, extracting the
 * `doPost` body. Each case becomes a labeled input for the detection pipeline:
 *
 *   real vulnerability = true  → expected "TP" (our pipeline should flag it)
 *   real vulnerability = false → expected "FP" (safe variant; should NOT flag)
 *
 * This drives the same `detectInCode` primitive as the other detection
 * benchmarks, so scores are comparable. (The heavyweight "official" path runs the
 * actual Maven suite + BenchmarkUtils scorecard — see runners/owasp-benchmark.ts.)
 */
import * as fs from "fs";
import * as path from "path";
import { OWASP_EXPECTED_CSV, OWASP_TESTCODE_DIR } from "../setup/owasp-benchmark";

export interface OwaspFullCase {
  testName: string; // BenchmarkTest00001
  category: string; // pathtraver | sqli | xss | ...
  cweId: string; // CWE-22
  expected: "TP" | "FP";
  code: string; // doPost body (or file head)
}

export interface OwaspFullOptions {
  /** Only this OWASP category (e.g. "sqli"). */
  category?: string;
  /** Limit number of cases (after category filter). */
  top?: number;
}

const MAX_CODE = 20000;

/** Extract the doPost body if present, else the head of the file. */
function extractDoPost(source: string): string {
  const idx = source.indexOf("doPost");
  if (idx >= 0) return source.slice(idx, idx + MAX_CODE);
  return source.slice(0, MAX_CODE);
}

export async function parseOwaspFullCases(
  opts: OwaspFullOptions = {}
): Promise<{ cases: OwaspFullCase[]; total: number; missingSource: number }> {
  if (!fs.existsSync(OWASP_EXPECTED_CSV)) {
    console.warn("   ⚠ OWASP Benchmark not found — run `npm run benchmark:setup -- --source=owasp-full` first.");
    return { cases: [], total: 0, missingSource: 0 };
  }

  const lines = fs.readFileSync(OWASP_EXPECTED_CSV, "utf8").split(/\r?\n/);
  const cases: OwaspFullCase[] = [];
  let missingSource = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const cols = trimmed.split(",").map((c) => c.trim());
    if (cols.length < 4) continue;
    const [testName, category, realRaw, cweRaw] = cols;
    if (!/^BenchmarkTest\d+$/i.test(testName)) continue;

    const expected: "TP" | "FP" | null =
      realRaw.toLowerCase() === "true" ? "TP" : realRaw.toLowerCase() === "false" ? "FP" : null;
    if (!expected) continue;
    if (opts.category && category.toLowerCase() !== opts.category.toLowerCase()) continue;

    const cweId = `CWE-${cweRaw.replace(/\D/g, "")}`;
    const javaPath = path.join(OWASP_TESTCODE_DIR, `${testName}.java`);
    let code = "";
    if (fs.existsSync(javaPath)) {
      try {
        code = extractDoPost(fs.readFileSync(javaPath, "utf8"));
      } catch {
        code = "";
      }
    }
    if (!code) {
      missingSource++;
      continue;
    }

    cases.push({ testName, category, cweId, expected, code });
    if (opts.top && cases.length >= opts.top) break;
  }

  return { cases, total: cases.length + missingSource, missingSource };
}

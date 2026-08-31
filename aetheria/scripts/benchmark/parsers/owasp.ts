/**
 * OWASP Benchmark parser.
 *
 * The OWASP Benchmark (Java) ships ~2,740 test cases (`BenchmarkTest#####.java`)
 * with ground-truth labels. We read labels from an `expectedresults.csv` placed
 * in `vendor/fp/owasp/` with rows:
 *
 *     BenchmarkTest00001,CWE-89,sqli,TP
 *     BenchmarkTest00002,CWE-79,xss,FP
 *
 * (last column accepts TP/FP or true/false). For each labeled test we load the
 * matching `.java` file and extract a bounded snippet around the sink. Returns
 * [] when the dataset/CSV is absent (it is a large external download).
 */
import * as fs from "fs";
import * as path from "path";
import { VENDOR_ROOT } from "../../../src/lib/knowledge/fp-sync/orchestrator";
import type { BenchmarkCaseInput } from "../../../src/lib/knowledge/fp-sync/types";

const OWASP_DIR = path.join(VENDOR_ROOT, "owasp");
const CSV_PATH = path.join(OWASP_DIR, "expectedresults.csv");
const MAX_SNIPPET = 2000;

function normalizeExpected(raw: string): "TP" | "FP" | null {
  const v = raw.trim().toLowerCase();
  if (v === "tp" || v === "true" || v === "real" || v === "1") return "TP";
  if (v === "fp" || v === "false" || v === "fake" || v === "0") return "FP";
  return null;
}

/** Extract a bounded snippet: the doPost/doGet body if present, else the head. */
function extractSnippet(source: string): string {
  const m = /(?:doPost|doGet|run)\s*\([^)]*\)\s*(?:throws[^{]*)?\{/.exec(source);
  if (m) {
    const start = m.index;
    return source.slice(start, start + MAX_SNIPPET);
  }
  return source.slice(0, MAX_SNIPPET);
}

export async function parseOwaspCases(): Promise<BenchmarkCaseInput[]> {
  if (!fs.existsSync(CSV_PATH)) return [];

  const lines = fs.readFileSync(CSV_PATH, "utf8").split(/\r?\n/).filter((l) => l.trim());
  const cases: BenchmarkCaseInput[] = [];

  for (const line of lines) {
    const cols = line.split(",").map((c) => c.trim());
    if (cols.length < 4) continue;
    const [testName, cweRaw, category, expectedRaw] = cols;
    if (!/^BenchmarkTest\d+$/i.test(testName)) continue; // skip header/notes
    const cweId = /CWE-\d+/i.test(cweRaw) ? cweRaw.toUpperCase() : `CWE-${cweRaw.replace(/\D/g, "")}`;
    const expected = normalizeExpected(expectedRaw);
    if (!expected) continue;

    const javaPath = path.join(OWASP_DIR, `${testName}.java`);
    let snippet = "";
    if (fs.existsSync(javaPath)) {
      try {
        snippet = extractSnippet(fs.readFileSync(javaPath, "utf8"));
      } catch {
        snippet = "";
      }
    }
    cases.push({ cweId, category: category || "unknown", expected, snippet, language: "java" });
  }

  return cases;
}

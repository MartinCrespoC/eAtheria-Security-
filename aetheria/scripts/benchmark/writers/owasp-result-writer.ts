/**
 * OWASP Benchmark — result writer (official-path integration).
 *
 * The official OWASP Benchmark scorecard (BenchmarkUtils) consumes per-tool result
 * files that map every `BenchmarkTest#####` to a boolean "did the tool flag it".
 * This writer turns AETHERIA's detections into that shape, emitting:
 *
 *   - an XML results file following the Benchmark's test-case schema, and
 *   - a companion CSV (`test name, category, cwe, detected`) for easy inspection
 *     and for feeding a custom scorecard.
 *
 * NOTE: having BenchmarkUtils score these files directly requires a reader for
 * AETHERIA on the BenchmarkUtils side (a Java integration in that repo). This
 * writer produces the canonical test-case→result mapping so that integration is a
 * thin step; the "lite" runner scores the same detections with our own
 * OWASP-formula scorecard (Score = TPR - FPR) in the meantime.
 */
import * as fs from "fs";
import * as path from "path";

export interface OwaspTestResult {
  testName: string; // BenchmarkTest00001
  category: string; // pathtraver
  cweId: string; // CWE-22
  detected: boolean; // did AETHERIA report a (kept) finding for this case?
}

function escapeXml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Write AETHERIA results in OWASP Benchmark format.
 * Returns the paths of the files written.
 */
export function writeOwaspResults(
  results: OwaspTestResult[],
  outDir: string,
  toolVersion = "1.0"
): { xmlPath: string; csvPath: string } {
  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const xmlPath = path.join(outDir, `AETHERIA-${stamp}.xml`);
  const csvPath = path.join(outDir, `AETHERIA-${stamp}.csv`);

  // ── XML (Benchmark test-case schema) ──
  const xmlLines: string[] = [];
  xmlLines.push(`<?xml version="1.0" encoding="UTF-8"?>`);
  xmlLines.push(`<OWASPBenchmark tool="AETHERIA" version="${escapeXml(toolVersion)}" date="${new Date().toISOString()}">`);
  for (const r of results) {
    xmlLines.push(`  <test-case>`);
    xmlLines.push(`    <name>${escapeXml(r.testName)}</name>`);
    xmlLines.push(`    <category>${escapeXml(r.category)}</category>`);
    xmlLines.push(`    <cwe>${escapeXml(r.cweId.replace(/\D/g, ""))}</cwe>`);
    xmlLines.push(`    <result>${r.detected ? "true" : "false"}</result>`);
    xmlLines.push(`  </test-case>`);
  }
  xmlLines.push(`</OWASPBenchmark>`);
  fs.writeFileSync(xmlPath, xmlLines.join("\n") + "\n");

  // ── CSV (easy to inspect / feed a custom scorecard) ──
  const csvLines: string[] = ["# test name, category, cwe, detected"];
  for (const r of results) {
    csvLines.push(`${r.testName},${r.category},${r.cweId.replace(/\D/g, "")},${r.detected}`);
  }
  fs.writeFileSync(csvPath, csvLines.join("\n") + "\n");

  return { xmlPath, csvPath };
}

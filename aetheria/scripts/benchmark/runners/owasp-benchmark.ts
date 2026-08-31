/**
 * OWASP Benchmark — runner.
 *
 * Runs AETHERIA's detection pipeline over the official OWASP Benchmark test cases
 * and scores the result OWASP-style (Score = TPR - FPR).
 *
 *   mode "lite"     (default): read labels + Java sources, run `detectInCode` on
 *                    each case, score with our scorecard, persist + report. No
 *                    Java/Maven needed.
 *   mode "official": everything in lite, PLUS emit AETHERIA results in the OWASP
 *                    Benchmark results format (XML + CSV) for the official
 *                    BenchmarkUtils scorecard. Actually invoking BenchmarkUtils
 *                    requires Maven + a reader integration (documented in
 *                    writers/owasp-result-writer.ts); this mode produces the
 *                    canonical result files and reports our own score alongside.
 */
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../../src/lib/db";
import type { ScanLevel } from "../../../src/lib/analysis/scan-knowledge";
import { detectInCode, hasKeptFindingForCwe } from "../detect";
import { parseOwaspFullCases } from "../parsers/owasp-full";
import { computeScores, printScorecard, type CaseResult } from "../scorecard";
import { writeOwaspResults, type OwaspTestResult } from "../writers/owasp-result-writer";
import { writeSarif, type SarifFinding } from "../writers/sarif-writer";
import { OWASP_BENCHMARK_DIR } from "../setup/owasp-benchmark";

export interface OwaspRunOptions {
  mode?: "lite" | "official";
  category?: string;
  top?: number;
  name?: string;
  scanLevel?: ScanLevel;
  withAi?: boolean;
}

export async function runOwaspBenchmark(opts: OwaspRunOptions = {}): Promise<void> {
  const mode = opts.mode ?? "lite";
  const scanLevel: ScanLevel = opts.scanLevel ?? "STATIC";
  const withAi = opts.withAi ?? false;
  const name =
    opts.name ??
    `owasp-full-${mode}-${opts.category ?? "all"}${opts.top ? `-top${opts.top}` : ""}-${new Date().toISOString().slice(0, 19)}`;

  console.log("🎯 OWASP Benchmark (official test suite)");
  console.log("═══════════════════════════════════════════");
  console.log(`   Mode:       ${mode}`);
  console.log(`   Category:   ${opts.category ?? "all"}`);
  console.log(`   Scan level: ${scanLevel}`);
  console.log(`   Run name:   ${name}`);
  console.log("═══════════════════════════════════════════\n");

  const { cases, missingSource } = await parseOwaspFullCases({ category: opts.category, top: opts.top });
  console.log(`📦 ${cases.length} labeled test cases${missingSource ? ` (${missingSource} missing source skipped)` : ""}\n`);

  if (cases.length === 0) {
    console.log("⚠ No OWASP Benchmark cases found. Run `npm run benchmark:setup -- --source=owasp-full` first.");
    return;
  }

  const results: CaseResult[] = [];
  const owaspResults: OwaspTestResult[] = [];
  const caseRows: { cweId: string; category: string; expected: string; detected: string; correct: boolean; snippet: string }[] = [];

  let i = 0;
  for (const c of cases) {
    i++;
    const outcomes = await detectInCode({
      fileContent: c.code,
      filePath: `${c.testName}.java`,
      language: "java",
      scanLevel,
      withAi,
    });
    const detected = hasKeptFindingForCwe(outcomes, c.cweId);
    const detectedLabel: "TP" | "FP" = detected ? "TP" : "FP";
    const correct = detectedLabel === c.expected;

    results.push({ cweId: c.cweId, category: c.category, expected: c.expected, detected: detectedLabel, correct });
    owaspResults.push({ testName: c.testName, category: c.category, cweId: c.cweId, detected });
    caseRows.push({
      cweId: c.cweId,
      category: c.category,
      expected: c.expected,
      detected: detectedLabel,
      correct,
      snippet: `[${c.testName}] ${c.code.slice(0, 900)}`,
    });

    if (i % 250 === 0 || i === cases.length) console.log(`   … ${i}/${cases.length} test cases processed`);
  }

  const card = computeScores(results);

  // ── Persist run + cases ──
  const run = await prisma.benchmarkRun.create({
    data: {
      name,
      source: "owasp-full",
      kind: "detection",
      totalCases: results.length,
      tpr: card.overall.tpr,
      fpr: card.overall.fpr,
      precision: card.overall.precision,
      recall: card.overall.recall,
      score: card.overall.score,
      byCategory: card.byCategory as object,
      metrics: {
        standard: "owasp-benchmark",
        benchmarkVersion: "1.2",
        mode,
        scanLevel,
        withAi,
        missingSource,
      } as object,
    },
  });
  await prisma.benchmarkCase.createMany({ data: caseRows.map((r) => ({ ...r, runId: run.id })) });

  // ── Report ──
  printScorecard(card);
  const correctCount = results.filter((r) => r.correct).length;
  console.log(`\n   Accuracy: ${correctCount}/${results.length} (${((correctCount / results.length) * 100).toFixed(1)}%)`);
  console.log(`   Run id:   ${run.id}`);

  // ── Official mode: emit OWASP-format results + SARIF ──
  if (mode === "official") {
    const outDir = path.join(OWASP_BENCHMARK_DIR, "results");
    const { xmlPath, csvPath } = writeOwaspResults(owaspResults, outDir);
    console.log(`\n📤 OWASP-format results written:`);
    console.log(`   XML: ${xmlPath}`);
    console.log(`   CSV: ${csvPath}`);

    // SARIF output: emit all kept findings in standard SARIF 2.1.0 format.
    const sarifFindings: SarifFinding[] = owaspResults
      .filter((r) => r.detected)
      .map((r) => ({
        cweId: r.cweId,
        category: r.category,
        title: `${r.category}: ${r.cweId} in ${r.testName}`,
        description: `AETHERIA detected ${r.category} (${r.cweId}) in ${r.testName}.java`,
        filePath: `${r.testName}.java`,
        lineStart: 1,
        lineEnd: 1,
        severity: "HIGH",
        confidence: 90,
      }));
    const sarifPath = writeSarif(sarifFindings, outDir, { runName: name });
    console.log(`   SARIF: ${sarifPath}`);
    console.log("   ℹ Scoring with the official BenchmarkUtils scorecard requires Maven and a");
    console.log("     BenchmarkUtils reader for AETHERIA — see writers/owasp-result-writer.ts.");
  }

  // ── JSON report to disk ──
  const reportDir = path.join(process.cwd(), "scripts", "benchmark", "reports");
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `${run.id}.json`);
  fs.writeFileSync(
    reportPath,
    JSON.stringify(
      { run: name, source: "owasp-full", kind: "detection", mode, scanLevel, overall: card.overall, byCategory: card.byCategory },
      null,
      2
    )
  );
  console.log(`\n💾 Report: ${reportPath}`);
}

/**
 * Benchmark Runner — measures the false-positive detector against labeled cases.
 *
 * For every case it calls `falsePositiveDetector.checkVulnerability` and records
 * whether the detector KEPT the finding (detected "TP") or DISMISSED it as a FP
 * (detected "FP"), then scores the result OWASP-Benchmark-style and persists a
 * `BenchmarkRun` + `BenchmarkCase` history row.
 *
 * Usage:
 *   npm run benchmark:run                              # curated baseline
 *   npm run benchmark:run -- --source=all              # curated + owasp + juliet (if present)
 *   npm run benchmark:run -- --source=curated --name="after-sync"
 *   npm run benchmark:run -- --scan-level=DEEP
 *   npm run benchmark:run -- --source=cve-benchmark                       # OpenSSF CVE Benchmark (top 25)
 *   npm run benchmark:run -- --source=cve-benchmark --all                 # full CVE set
 *   npm run benchmark:run -- --source=cve-benchmark --cve=CVE-2017-16014  # single CVE
 *   npm run benchmark:run -- --source=cve-benchmark --top=50
 *   npm run benchmark:run -- --source=owasp-full                          # OWASP Benchmark (lite, all cases)
 *   npm run benchmark:run -- --source=owasp-full --category=sqli --top=50
 *   npm run benchmark:run -- --source=owasp-full --mode=official          # also emit OWASP-format results
 *   npm run benchmark:run -- --source=scorecard                           # OpenSSF Scorecard (AETHERIA repo)
 *   npm run benchmark:run -- --source=scorecard --repo=ossf/scorecard
 *   npm run benchmark:run -- --source=badge                              # Best Practices Badge (passing tier)
 *   npm run benchmark:run -- --source=badge --tier=silver
 */
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../src/lib/db";
import { falsePositiveDetector } from "../../src/lib/analysis/false-positive-detector";
import type { ScanLevel } from "../../src/lib/analysis/scan-knowledge";
import type { BenchmarkCaseInput } from "../../src/lib/knowledge/fp-sync/types";
import { CURATED_BENCHMARK_CASES } from "./parsers/curated";
import { parseOwaspCases } from "./parsers/owasp";
import { parseJulietCases } from "./parsers/juliet";
import { parseWstgCases } from "./parsers/wstg";
import { computeScores, printScorecard, type CaseResult } from "./scorecard";
import { runCveBenchmark } from "./runners/cve-benchmark";
import { runOwaspBenchmark } from "./runners/owasp-benchmark";
import { assessScorecard } from "./assess/scorecard";
import { assessBadge } from "./assess/badge";
import type { BadgeTier } from "../../src/lib/knowledge/fp-sync/adapters/badge";

interface Args {
  sources: string[];
  name: string;
  scanLevel: ScanLevel;
  cve?: string;
  cves?: string[];
  top?: number;
  all?: boolean;
  withAi?: boolean;
  projectContext?: boolean;
  mode?: "lite" | "official";
  category?: string;
  repo?: string;
  tier?: BadgeTier;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { sources: ["curated"], name: "", scanLevel: "STATIC" };
  for (const arg of argv) {
    if (arg.startsWith("--source=")) {
      const raw = arg.slice("--source=".length).toLowerCase();
      args.sources = raw === "all" ? ["curated", "owasp", "juliet", "wstg"] : raw.split(",").map((s) => s.trim());
    } else if (arg.startsWith("--name=")) {
      args.name = arg.slice("--name=".length);
    } else if (arg.startsWith("--scan-level=")) {
      const lvl = arg.slice("--scan-level=".length).toUpperCase();
      if (lvl === "STATIC" || lvl === "LIGHTWEIGHT" || lvl === "DEEP") args.scanLevel = lvl;
    } else if (arg.startsWith("--cve=")) {
      args.cve = arg.slice("--cve=".length);
    } else if (arg.startsWith("--cves=")) {
      args.cves = arg.slice("--cves=".length).split(",").map((s) => s.trim()).filter(Boolean);
    } else if (arg.startsWith("--top=")) {
      const n = parseInt(arg.slice("--top=".length), 10);
      if (!Number.isNaN(n) && n > 0) args.top = n;
    } else if (arg === "--all") {
      args.all = true;
    } else if (arg === "--with-ai") {
      args.withAi = true;
    } else if (arg === "--project-context") {
      args.projectContext = true;
    } else if (arg.startsWith("--mode=")) {
      const m = arg.slice("--mode=".length).toLowerCase();
      if (m === "lite" || m === "official") args.mode = m;
    } else if (arg.startsWith("--category=")) {
      args.category = arg.slice("--category=".length);
    } else if (arg.startsWith("--repo=")) {
      args.repo = arg.slice("--repo=".length);
    } else if (arg.startsWith("--tier=")) {
      const t = arg.slice("--tier=".length).toLowerCase();
      if (t === "passing" || t === "silver" || t === "gold") args.tier = t;
    }
  }
  if (!args.name) args.name = `fp-benchmark-${args.sources.join("+")}-${new Date().toISOString().slice(0, 19)}`;
  return args;
}

async function gatherCases(sources: string[]): Promise<{ cases: BenchmarkCaseInput[]; sourceLabel: string }> {
  const cases: BenchmarkCaseInput[] = [];
  const used = new Set<string>();
  const push = (list: BenchmarkCaseInput[]) => {
    for (const c of list) {
      const key = `${c.cweId}|${c.expected}|${c.snippet}`;
      if (used.has(key)) continue;
      used.add(key);
      cases.push(c);
    }
  };
  for (const src of sources) {
    if (src === "curated") push(CURATED_BENCHMARK_CASES);
    else if (src === "owasp") push(await parseOwaspCases());
    else if (src === "juliet") push(await parseJulietCases());
    else if (src === "wstg") push(await parseWstgCases());
  }
  return { cases, sourceLabel: sources.join("+") };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  // The OpenSSF CVE Benchmark is a distinct pipeline (detect on vulnerable vs
  // patched real-world code), so it runs through its own runner.
  if (args.sources.includes("cve-benchmark")) {
    await runCveBenchmark({
      cve: args.cve,
      cves: args.cves,
      top: args.top,
      all: args.all,
      name: args.name,
      scanLevel: args.scanLevel,
      withAi: args.withAi,
      projectContext: args.projectContext,
    });
    return;
  }

  // The OWASP Benchmark (official test suite) is also a distinct pipeline: it
  // reads ground-truth labels + Java sources and scores OWASP-style.
  if (args.sources.includes("owasp-full")) {
    await runOwaspBenchmark({
      mode: args.mode,
      category: args.category,
      top: args.top,
      name: args.name,
      scanLevel: args.scanLevel,
      withAi: args.withAi,
    });
    return;
  }

  // OpenSSF Scorecard is an *assessment* (posture scoring), not a detection
  // benchmark, so it runs through its own assess pipeline.
  if (args.sources.includes("scorecard")) {
    await assessScorecard({ repo: args.repo, name: args.name });
    return;
  }

  // OpenSSF Best Practices Badge is also an *assessment* (self-scored criteria).
  if (args.sources.includes("badge") || args.sources.includes("best-practices-badge")) {
    await assessBadge({ tier: args.tier, name: args.name });
    return;
  }

  console.log("🎯 FP Detector Benchmark");
  console.log("═══════════════════════════════════════════");
  console.log(`   Sources:    ${args.sources.join(", ")}`);
  console.log(`   Scan level: ${args.scanLevel}`);
  console.log(`   Run name:   ${args.name}`);
  console.log("═══════════════════════════════════════════\n");

  const { cases, sourceLabel } = await gatherCases(args.sources);
  if (cases.length === 0) {
    console.log("⚠ No benchmark cases found. Curated should always be available;");
    console.log("  OWASP/Juliet require placing the datasets under vendor/fp/.");
    return;
  }
  console.log(`📦 Loaded ${cases.length} labeled cases\n`);

  await falsePositiveDetector.initialize();

  const results: CaseResult[] = [];
  const caseRows: { cweId: string; category: string; expected: string; detected: string; correct: boolean; snippet: string }[] = [];
  const mistakes: { c: BenchmarkCaseInput; detected: string }[] = [];

  for (const c of cases) {
    const fp = await falsePositiveDetector.checkVulnerability({
      cweId: c.cweId,
      code: c.snippet,
      codeSnippet: c.snippet,
      language: c.language,
      line: 0,
      file: `benchmark/${c.category}`,
      severity: "HIGH",
      scanLevel: args.scanLevel,
    });
    const detected: "TP" | "FP" = fp.isFalsePositive ? "FP" : "TP";
    const correct = detected === c.expected;
    results.push({ cweId: c.cweId, category: c.category, expected: c.expected, detected, correct });
    caseRows.push({ cweId: c.cweId, category: c.category, expected: c.expected, detected, correct, snippet: c.snippet.slice(0, 1000) });
    if (!correct) mistakes.push({ c, detected });
  }

  const card = computeScores(results);

  // ── Persist run + cases ──
  const run = await prisma.benchmarkRun.create({
    data: {
      name: args.name,
      source: sourceLabel,
      totalCases: results.length,
      tpr: card.overall.tpr,
      fpr: card.overall.fpr,
      precision: card.overall.precision,
      recall: card.overall.recall,
      score: card.overall.score,
      byCategory: card.byCategory as object,
    },
  });
  await prisma.benchmarkCase.createMany({
    data: caseRows.map((r) => ({ ...r, runId: run.id })),
  });

  // ── Report ──
  printScorecard(card);
  const correctCount = results.filter((r) => r.correct).length;
  console.log(`\n   Accuracy: ${correctCount}/${results.length} (${((correctCount / results.length) * 100).toFixed(1)}%)`);
  console.log(`   Run id:   ${run.id}`);

  if (mistakes.length) {
    console.log("\n✗ Misclassified cases:");
    for (const m of mistakes) {
      console.log(`   - ${m.c.cweId} [${m.c.category}] expected ${m.c.expected}, got ${m.detected}`);
      console.log(`     ${m.c.snippet.replace(/\n/g, " ").slice(0, 120)}`);
    }
  }

  // ── JSON report to disk ──
  const reportDir = path.join(process.cwd(), "scripts", "benchmark", "reports");
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `${run.id}.json`);
  fs.writeFileSync(
    reportPath,
    JSON.stringify({ run: args.name, source: sourceLabel, scanLevel: args.scanLevel, overall: card.overall, byCategory: card.byCategory, mistakes: mistakes.map((m) => ({ cweId: m.c.cweId, category: m.c.category, expected: m.c.expected, detected: m.detected, snippet: m.c.snippet })) }, null, 2)
  );
  console.log(`\n💾 Report: ${reportPath}`);
}

main()
  .catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

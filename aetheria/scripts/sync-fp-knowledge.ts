/**
 * FP Knowledge Sync CLI
 *
 * Ingests false-positive knowledge from external sources (gitleaks, MITRE CWE,
 * Semgrep, NIST Juliet) into the database. Mirrors scripts/sync-bughunter.ts.
 *
 * Usage:
 *   npm run sync:fp                      # sync all sources
 *   npm run sync:fp -- --source=gitleaks # sync a single source
 *   npm run sync:fp -- --source=cwe,semgrep --force
 *
 * Flags:
 *   --source=<id,id>   Only run these source ids (default: all)
 *   --force            Re-parse/upsert even if the content checksum is unchanged
 */
import { prisma } from "../src/lib/db";
import { syncFpKnowledge } from "../src/lib/knowledge/fp-sync/orchestrator";
import { ALL_FP_ADAPTERS } from "../src/lib/knowledge/fp-sync/adapters";
import type { SyncOptions } from "../src/lib/knowledge/fp-sync/types";

function parseArgs(argv: string[]): SyncOptions {
  const options: SyncOptions = {};
  for (const arg of argv) {
    if (arg.startsWith("--source=")) {
      options.sources = arg
        .slice("--source=".length)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "--force") {
      options.force = true;
    } else if (arg === "--skip-benchmark") {
      options.skipBenchmark = true;
    }
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  console.log("🧠 FP Knowledge Sync");
  console.log("═══════════════════════════════════════════");
  console.log(`   Sources: ${options.sources?.join(", ") ?? "all"}`);
  console.log(`   Force:   ${options.force ? "yes" : "no"}`);
  console.log("═══════════════════════════════════════════");

  const allStats = await syncFpKnowledge(ALL_FP_ADAPTERS, options);

  // ── Per-source summary ──
  console.log("\n═══════════════════════════════════════════");
  console.log("📊 Sync Summary");
  console.log("═══════════════════════════════════════════");
  let totCreated = 0;
  let totUpdated = 0;
  let totSkipped = 0;
  let totCwe = 0;
  let totErrors = 0;
  for (const s of allStats) {
    totCreated += s.patternsCreated;
    totUpdated += s.patternsUpdated;
    totSkipped += s.patternsSkipped;
    totCwe += s.cweUpserted;
    totErrors += s.errors.length;
    const status = s.errors.length ? "✗ error" : "✓ ok";
    console.log(
      `   [${status}] ${s.source.padEnd(9)} patterns +${s.patternsCreated}/~${s.patternsUpdated} ` +
        `(skip ${s.patternsSkipped}) · cwe ${s.cweUpserted} · ${s.durationMs}ms`
    );
    for (const err of s.errors) console.log(`        ⚠ ${err}`);
  }

  console.log("───────────────────────────────────────────");
  console.log(
    `   TOTAL patterns +${totCreated}/~${totUpdated} (skip ${totSkipped}) · cwe ${totCwe} · errors ${totErrors}`
  );

  // ── DB state ──
  const [patternCount, builtinCount, ingestedCount, cweCount, sourceCount] = await Promise.all([
    prisma.falsePositivePattern.count(),
    prisma.falsePositivePattern.count({ where: { source: "builtin" } }),
    prisma.falsePositivePattern.count({ where: { source: { notIn: ["builtin", "manual"] } } }),
    prisma.cweKnowledge.count(),
    prisma.fpKnowledgeSource.count(),
  ]);
  console.log("\n✅ Database state:");
  console.log(`   FP patterns:    ${patternCount} (builtin ${builtinCount}, ingested ${ingestedCount})`);
  console.log(`   CWE knowledge:  ${cweCount}`);
  console.log(`   Sync sources:   ${sourceCount}`);

  if (totErrors > 0) process.exitCode = 1;
}

main()
  .catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

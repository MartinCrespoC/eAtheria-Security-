/**
 * Benchmark setup dispatcher.
 *
 * Prepares the external datasets each industry-standard benchmark needs (cloning
 * metadata repos, warming caches). Idempotent and non-fatal per source — mirrors
 * the sync-bughunter / fp-sync orchestrator pattern.
 *
 * Usage:
 *   npm run benchmark:setup                              # all standards
 *   npm run benchmark:setup -- --source=cve-benchmark    # one standard
 *   npm run benchmark:setup -- --source=cve-benchmark,owasp-full
 */
import { setupCveBenchmark } from "./setup/cve-benchmark";
import { setupOwaspBenchmark } from "./setup/owasp-benchmark";
import { setupScorecard } from "./setup/scorecard";
import { setupBadge } from "./setup/badge";
import { setupWstg } from "./setup/wstg";

interface SetupFn {
  (): unknown;
}

const SETUPS: Record<string, SetupFn> = {
  "cve-benchmark": setupCveBenchmark,
  "owasp-full": setupOwaspBenchmark,
  scorecard: setupScorecard,
  badge: setupBadge,
  wstg: setupWstg,
};

function parseSources(argv: string[]): string[] {
  for (const arg of argv) {
    if (arg.startsWith("--source=")) {
      const raw = arg.slice("--source=".length).toLowerCase();
      return raw === "all" ? Object.keys(SETUPS) : raw.split(",").map((s) => s.trim());
    }
  }
  return Object.keys(SETUPS);
}

function main() {
  const sources = parseSources(process.argv.slice(2));
  console.log("🧰 Benchmark setup");
  console.log(`   Standards: ${sources.join(", ")}`);

  let ok = 0;
  let failed = 0;
  for (const src of sources) {
    const fn = SETUPS[src];
    if (!fn) {
      console.warn(`\n   ⚠ Unknown standard "${src}" (available: ${Object.keys(SETUPS).join(", ")})`);
      failed++;
      continue;
    }
    try {
      fn();
      ok++;
    } catch (err) {
      failed++;
      console.error(`\n   ✗ [${src}] setup failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  console.log(`\n✅ Setup complete: ${ok} ok, ${failed} failed`);
}

main();

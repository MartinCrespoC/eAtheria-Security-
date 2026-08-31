/**
 * OWASP Benchmark — setup.
 *
 * Clones the official OWASP Benchmark (Java, ~2,740 servlet test cases with
 * ground-truth labels in `expectedresults-1.2.csv`) into `vendor/fp/owasp-benchmark`.
 *
 * Two ways to use it (see parsers/owasp-full.ts + runners/owasp-benchmark.ts):
 *   - "lite"    (default, no Java needed): read the labels + `.java` sources and
 *     run AETHERIA's detection pipeline directly over each test case.
 *   - "official" (requires Java 11+ AND Maven): build the suite with
 *     `mvn -DskipTests package`, run it, and score AETHERIA with the official
 *     BenchmarkUtils scorecard. This setup will attempt the build only when
 *     Maven is present and `--build` is passed; otherwise it documents the steps.
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { ensureGitRepo, VENDOR_ROOT } from "../../../src/lib/knowledge/fp-sync/orchestrator";

export const OWASP_BENCHMARK_REPO = "https://github.com/OWASP-Benchmark/Benchmark.git";
export const OWASP_BENCHMARK_DIR = path.join(VENDOR_ROOT, "owasp-benchmark");
export const OWASP_EXPECTED_CSV = path.join(OWASP_BENCHMARK_DIR, "expectedresults-1.2.csv");
export const OWASP_TESTCODE_DIR = path.join(
  OWASP_BENCHMARK_DIR,
  "src",
  "main",
  "java",
  "org",
  "owasp",
  "benchmark",
  "testcode"
);

function mavenAvailable(): boolean {
  try {
    execFileSync("mvn", ["-version"], { stdio: "pipe", timeout: 30000 });
    return true;
  } catch {
    return false;
  }
}

/** Clone/pull the OWASP Benchmark and (optionally) build it for the official path. */
export function setupOwaspBenchmark(opts: { build?: boolean } = {}): { testCases: number; dir: string } {
  console.log("\n📦 [owasp-full] OWASP Benchmark setup");
  ensureGitRepo(OWASP_BENCHMARK_REPO, OWASP_BENCHMARK_DIR);

  let testCases = 0;
  if (fs.existsSync(OWASP_TESTCODE_DIR)) {
    testCases = fs.readdirSync(OWASP_TESTCODE_DIR).filter((f) => /^BenchmarkTest\d+\.java$/.test(f)).length;
  }
  console.log(`   ✓ ${testCases} test cases at ${OWASP_TESTCODE_DIR}`);
  console.log(`   ✓ labels at ${OWASP_EXPECTED_CSV}`);

  if (opts.build) {
    if (!mavenAvailable()) {
      console.warn("   ⚠ Maven not found — skipping official build.");
      console.warn("     The 'official' mode needs Java 11+ and Maven. Install Maven, then:");
      console.warn(`       cd ${OWASP_BENCHMARK_DIR} && mvn -DskipTests package`);
    } else {
      console.log("   🔨 Building with Maven (mvn -DskipTests package)… this can take several minutes.");
      try {
        execFileSync("mvn", ["-DskipTests", "package"], { cwd: OWASP_BENCHMARK_DIR, stdio: "inherit", timeout: 1800000 });
        console.log("   ✓ Maven build complete.");
      } catch (err) {
        console.warn(`   ⚠ Maven build failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  } else {
    console.log("   ℹ Lite mode needs no build. For the official harness pass --build (requires Maven).");
  }

  return { testCases, dir: OWASP_BENCHMARK_DIR };
}

/**
 * OpenSSF Scorecard — setup.
 *
 * Scorecard (https://github.com/ossf/scorecard) scores an OSS project's security
 * posture across ~17 checks (Code-Review, Security-Policy, Dependency-Update-Tool,
 * …) on a 0-10 scale. There are two ways to obtain a score, and this setup makes
 * both available:
 *
 *   1. The `scorecard` CLI binary  — runs the checks live against any repo (needs
 *      a GitHub token for full results). We detect it on PATH or in ~/go/bin.
 *   2. The public API (api.securityscorecards.dev) — free, no token, but only has
 *      scores for repos already in the OpenSSF dataset (public + indexed).
 *
 * Setup is idempotent and non-fatal: if the binary is missing it documents how to
 * install it and the assessment step falls back to the public API automatically.
 */
import { execFileSync } from "child_process";
import * as os from "os";
import * as path from "path";

export const SCORECARD_API_BASE = "https://api.securityscorecards.dev/projects";
export const SCORECARD_GO_PACKAGE = "github.com/ossf/scorecard/v5/cmd/scorecard@latest";

/** Candidate locations for the scorecard binary, in priority order. */
function candidatePaths(): string[] {
  const home = os.homedir();
  return [
    "scorecard", // on PATH
    path.join(home, "go", "bin", "scorecard"),
    path.join(home, ".local", "bin", "scorecard"),
  ];
}

/** Return the working scorecard binary path/command, or null if unavailable. */
export function findScorecardBinary(): string | null {
  for (const candidate of candidatePaths()) {
    // v5 removed the `--version` flag in favor of the `version` subcommand;
    // `--help` works on every release, so use it as the liveness probe.
    for (const probe of [["version"], ["--help"]]) {
      try {
        execFileSync(candidate, probe, { stdio: "pipe", timeout: 30000 });
        return candidate;
      } catch {
        // try next probe
      }
    }
  }
  return null;
}

/** Detect the scorecard binary and report how the assessment can run. */
export function setupScorecard(): { binary: string | null; apiBase: string } {
  console.log("\n📦 [scorecard] OpenSSF Scorecard setup");

  const binary = findScorecardBinary();
  if (binary) {
    let version = "unknown";
    try {
      version = execFileSync(binary, ["--version"], { stdio: "pipe", timeout: 30000 }).toString().trim().split("\n")[0];
    } catch {
      /* keep "unknown" */
    }
    console.log(`   ✓ scorecard binary found: ${binary} (${version})`);
    console.log("     Live runs need a GitHub token: export GITHUB_AUTH_TOKEN=…");
  } else {
    console.warn("   ⚠ scorecard binary not found. Install it for live runs:");
    console.warn(`       go install ${SCORECARD_GO_PACKAGE}`);
    console.warn("     or download a release binary from https://github.com/ossf/scorecard/releases");
    console.warn(`   ℹ Falling back to the public API at ${SCORECARD_API_BASE}`);
    console.warn("     (only repos already indexed by OpenSSF are available there).");
  }

  const hasToken = Boolean(process.env.GITHUB_AUTH_TOKEN || process.env.GITHUB_TOKEN);
  if (binary && !hasToken) {
    console.warn("   ⚠ No GITHUB_AUTH_TOKEN set — live runs may be rate-limited or incomplete.");
  }

  return { binary, apiBase: SCORECARD_API_BASE };
}

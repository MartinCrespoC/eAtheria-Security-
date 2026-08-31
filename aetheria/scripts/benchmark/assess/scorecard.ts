/**
 * OpenSSF Scorecard — assessment runner.
 *
 * Scores a repository's security posture with OpenSSF Scorecard and persists the
 * result as an *assessment* `BenchmarkRun` (kind="assessment", score = overall/10).
 *
 * Two acquisition paths, tried in order:
 *   1. The `scorecard` CLI binary (live run, needs a GitHub token for full data).
 *   2. The public API at api.securityscorecards.dev (no token, but only repos
 *      already indexed by OpenSSF are present).
 *
 * Both return the same shape — `{repo, score, checks:[{name,score,reason}]}` — so
 * a single normalizer feeds the persistence + report regardless of the source.
 *
 * Usage:
 *   npm run benchmark:run -- --source=scorecard                    # AETHERIA repo
 *   npm run benchmark:run -- --source=scorecard --repo=ossf/scorecard
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../../src/lib/db";
import { findScorecardBinary, SCORECARD_API_BASE } from "../setup/scorecard";

export interface ScorecardCheck {
  name: string;
  score: number; // 0-10 (or -1 for "unknown/not applicable")
  reason: string;
}

export interface ScorecardAssessment {
  repo: string; // github.com/owner/name
  date?: string;
  scorecardVersion?: string;
  source: "binary" | "api";
  overallScore: number; // 0-10
  checks: ScorecardCheck[];
}

export interface ScorecardOptions {
  /** Repository as `owner/name` (default: the AETHERIA repo from git remote). */
  repo?: string;
  name?: string;
}

/** Default repository, derived from the git remote of the enclosing workspace. */
export function defaultRepo(): string {
  try {
    const url = execFileSync("git", ["config", "--get", "remote.origin.url"], {
      cwd: path.join(process.cwd(), ".."),
      stdio: "pipe",
      timeout: 15000,
    })
      .toString()
      .trim();
    const m = url.match(/github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/);
    if (m) return m[1];
  } catch {
    /* fall through */
  }
  return "MartinCrespoC/eAtheria-Security";
}

/** Run the scorecard CLI binary and return the parsed JSON, or null on failure. */
function runBinary(binary: string, repo: string): Record<string, unknown> | null {
  try {
    const out = execFileSync(binary, [`--repo=github.com/${repo}`, "--format=json"], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 600000,
      encoding: "utf8",
    });
    return JSON.parse(out) as Record<string, unknown>;
  } catch (err) {
    // A non-zero exit is non-fatal when scorecard still emitted JSON (some
    // checks fail on flaky network, e.g. the Fuzzing OSS-Fuzz lookup).
    const stdout = (err as { stdout?: string })?.stdout;
    if (stdout && stdout.trim().startsWith("{")) {
      try { return JSON.parse(stdout) as Record<string, unknown>; } catch { /* fall through */ }
    }
    console.warn(`   ⚠ scorecard binary run failed: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
    return null;
  }
}

/**
 * Run the scorecard CLI in --local mode on a CLEAN, TRACKED-ONLY snapshot of
 * HEAD (extracted via `git archive`). The worktree contains gitignored runtime
 * artifacts (uploads/, vendor datasets, .next/) that are not source code but
 * would otherwise be scored (Binary-Artifacts, Pinned-Dependencies) — scoring
 * the archive measures the repo as it is actually published.
 */
function runBinaryLocal(binary: string, dir: string): Record<string, unknown> | null {
  let snapshot: string | null = null;
  try {
    snapshot = fs.mkdtempSync(path.join(fs.realpathSync(process.env.TMPDIR ?? "/tmp"), "scorecard-clean-"));
    execFileSync("sh", ["-c", 'git archive HEAD | tar -x -C "$1"', "sh", snapshot], {
      cwd: dir,
      stdio: "pipe",
      timeout: 120000,
    });
  } catch (err) {
    console.warn(`   ⚠ clean snapshot extraction failed: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
    if (snapshot) fs.rmSync(snapshot, { recursive: true, force: true });
    return null;
  }
  try {
    const out = execFileSync(binary, [`--local=${snapshot}`, "--format=json"], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 600000,
      encoding: "utf8",
    });
    return JSON.parse(out) as Record<string, unknown>;
  } catch (err) {
    // A non-zero exit is non-fatal when scorecard still emitted JSON (some
    // checks fail on flaky network, e.g. the Fuzzing OSS-Fuzz lookup).
    const stdout = (err as { stdout?: string })?.stdout;
    if (stdout && stdout.trim().startsWith("{")) {
      try { return JSON.parse(stdout) as Record<string, unknown>; } catch { /* fall through */ }
    }
    const e = err as { message?: string; stderr?: Buffer | string };
    const stderrTail = e.stderr ? String(e.stderr).trim().split("\n").slice(-2).join(" | ") : "";
    console.warn(`   ⚠ scorecard --local run failed: ${(e.message ?? String(err)).split("\n")[0]}${stderrTail ? ` — ${stderrTail.slice(0, 300)}` : ""}`);
    return null;
  } finally {
    fs.rmSync(snapshot, { recursive: true, force: true });
  }
}

/** Query the public Scorecard API and return the parsed JSON, or null on failure. */
async function fetchApi(repo: string): Promise<Record<string, unknown> | null> {
  const url = `${SCORECARD_API_BASE}/github.com/${repo}`;
  try {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) {
      console.warn(`   ⚠ Scorecard API returned HTTP ${res.status} for ${repo}`);
      if (res.status === 404) {
        console.warn("     This repo is not in the public OpenSSF dataset (private or not yet indexed).");
        console.warn("     Install the scorecard binary + set GITHUB_AUTH_TOKEN for a live run.");
      }
      return null;
    }
    return (await res.json()) as Record<string, unknown>;
  } catch (err) {
    console.warn(`   ⚠ Scorecard API fetch failed: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

/** Normalize either source's JSON into a ScorecardAssessment. */
function normalize(json: Record<string, unknown>, source: "binary" | "api", repo: string): ScorecardAssessment {
  const repoName =
    (json.repo as { name?: string } | undefined)?.name ?? `github.com/${repo}`;
  const scorecard = json.scorecard as { version?: string } | undefined;
  const rawChecks = Array.isArray(json.checks) ? (json.checks as Array<Record<string, unknown>>) : [];
  const checks: ScorecardCheck[] = rawChecks.map((c) => ({
    name: String(c.name ?? "unknown"),
    score: typeof c.score === "number" ? c.score : -1,
    reason: String(c.reason ?? ""),
  }));
  return {
    repo: repoName,
    date: typeof json.date === "string" ? json.date : undefined,
    scorecardVersion: scorecard?.version,
    source,
    overallScore: typeof json.score === "number" ? json.score : 0,
    checks,
  };
}

/** Pretty-print the per-check breakdown. */
function printAssessment(a: ScorecardAssessment): void {
  console.log(`\n📊 OpenSSF Scorecard — ${a.repo}`);
  console.log(`   Source: ${a.source}${a.scorecardVersion ? ` · scorecard ${a.scorecardVersion}` : ""}${a.date ? ` · ${a.date}` : ""}`);
  console.log("═══════════════════════════════════════════");
  const nameW = Math.max(10, ...a.checks.map((c) => c.name.length)) + 2;
  console.log(`   ${"Check".padEnd(nameW)}Score   Reason`);
  console.log("   " + "─".repeat(Math.min(70, nameW + 40)));
  for (const c of a.checks) {
    const scoreStr = c.score < 0 ? "?" : String(c.score).padStart(2);
    console.log(`   ${c.name.padEnd(nameW)}${scoreStr}/10   ${c.reason.slice(0, 48)}`);
  }
  console.log("   " + "─".repeat(Math.min(70, nameW + 40)));
  console.log(`   OVERALL: ${a.overallScore}/10  (${(a.overallScore / 10).toFixed(2)} normalized)`);
}

export async function assessScorecard(opts: ScorecardOptions = {}): Promise<void> {
  const repo = opts.repo ?? defaultRepo();
  const name = opts.name ?? `scorecard-${repo.replace("/", "-")}-${new Date().toISOString().slice(0, 19)}`;

  console.log("🛡 OpenSSF Scorecard assessment");
  console.log("═══════════════════════════════════════════");
  console.log(`   Repo:     ${repo}`);
  console.log(`   Run name: ${name}`);
  console.log("═══════════════════════════════════════════\n");

  // ── Path 1: binary ──
  let assessment: ScorecardAssessment | null = null;
  const binary = findScorecardBinary();
  if (binary) {
    console.log(`   ▶ Running scorecard binary (${binary})…`);
    const json = runBinary(binary, repo);
    if (json) assessment = normalize(json, "binary", repo);
  } else {
    console.log("   ℹ No scorecard binary — using the public API.");
  }

  // ── Path 1b: binary --local fallback (no GitHub token needed) ──
  if (!assessment && binary) {
    const localRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: path.join(process.cwd(), ".."),
      stdio: "pipe",
      timeout: 15000,
      encoding: "utf8",
    }).trim();
    console.log(`   ▶ Retrying in --local mode (${localRoot})…`);
    const json = runBinaryLocal(binary, localRoot);
    if (json) assessment = normalize(json, "binary", repo);
  }

  // ── Path 2: public API fallback ──
  if (!assessment) {
    const json = await fetchApi(repo);
    if (json) assessment = normalize(json, "api", repo);
  }

  if (!assessment) {
    console.error(`\n✗ Could not obtain a Scorecard for ${repo} via binary or public API.`);
    console.error("  • Install the binary:  go install github.com/ossf/scorecard/v5/cmd/scorecard@latest");
    console.error("  • Set a token:         export GITHUB_AUTH_TOKEN=…");
    console.error("  • Or assess an indexed public repo:  --repo=ossf/scorecard");
    return;
  }

  printAssessment(assessment);

  // ── Persist (assessment run) ──
  const byCategory: Record<string, number> = {};
  for (const c of assessment.checks) byCategory[c.name] = c.score;

  const run = await prisma.benchmarkRun.create({
    data: {
      name,
      source: "scorecard",
      kind: "assessment",
      totalCases: assessment.checks.length,
      score: assessment.overallScore / 10, // normalized 0-1 headline
      byCategory: byCategory as object,
      metrics: {
        standard: "openssf-scorecard",
        repo: assessment.repo,
        date: assessment.date,
        scorecardVersion: assessment.scorecardVersion,
        acquisition: assessment.source,
        overallScore10: assessment.overallScore,
        checks: assessment.checks,
      } as object,
    },
  });

  console.log(`\n   Run id: ${run.id}`);

  // ── JSON report to disk ──
  const reportDir = path.join(process.cwd(), "scripts", "benchmark", "reports");
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `${run.id}.json`);
  fs.writeFileSync(
    reportPath,
    JSON.stringify(
      {
        run: name,
        source: "scorecard",
        kind: "assessment",
        repo: assessment.repo,
        acquisition: assessment.source,
        overallScore10: assessment.overallScore,
        normalized: assessment.overallScore / 10,
        checks: assessment.checks,
      },
      null,
      2
    )
  );
  console.log(`💾 Report: ${reportPath}`);
}

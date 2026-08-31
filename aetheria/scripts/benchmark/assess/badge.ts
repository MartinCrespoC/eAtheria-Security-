/**
 * OpenSSF Best Practices Badge — self-assessment runner.
 *
 * Scores the AETHERIA repository against the *automatable* subset of the OpenSSF
 * Best Practices Badge criteria and persists the result as an *assessment*
 * `BenchmarkRun` (kind="assessment", score = passing-tier percentage / 100).
 *
 * The badge programme defines ~145 criteria across three cumulative tiers
 * (passing → silver → gold). Only a portion can be decided automatically from a
 * repository checkout (presence of LICENSE / SECURITY.md / CONTRIBUTING, build &
 * test scripts, CI workflows, dependency monitoring, version tags, …). Each
 * automatable criterion is mapped to a deterministic filesystem/git probe below;
 * everything else is reported as "n/a (manual)" and excluded from the percentage.
 *
 * Usage:
 *   npm run benchmark:run -- --source=badge                    # passing tier
 *   npm run benchmark:run -- --source=badge --tier=silver
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../../src/lib/db";
import { parseBadgeCriteria, type BadgeCriterion, type BadgeTier } from "../../../src/lib/knowledge/fp-sync/adapters/badge";

export interface BadgeOptions {
  /** Tier whose percentage becomes the headline score (default: passing). */
  tier?: BadgeTier;
  name?: string;
}

const TIER_ORDER: BadgeTier[] = ["passing", "silver", "gold"];

/** Result of a single automated probe. `null` = not automatable / not applicable. */
type ProbeResult = boolean | null;

interface CheckCtx {
  /** Git toplevel (the assessed repository root). */
  root: string;
  /** Directory containing package.json (the Node app, e.g. `<root>/aetheria`). */
  app: string;
}

// ─────────────────────────── probe helpers ───────────────────────────

function firstExisting(base: string, rels: string[]): string | null {
  for (const rel of rels) {
    const p = path.join(base, rel);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/** Search for a file across the repo root and the app dir (case-insensitive name). */
function findInRepo(ctx: CheckCtx, names: string[]): string | null {
  for (const base of [ctx.app, ctx.root]) {
    try {
      const entries = fs.readdirSync(base);
      for (const n of names) {
        const hit = entries.find((e) => e.toLowerCase() === n.toLowerCase());
        if (hit) return path.join(base, hit);
      }
    } catch {
      /* ignore unreadable dir */
    }
  }
  return null;
}

function readText(p: string | null): string {
  if (!p) return "";
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

function readJson(p: string | null): Record<string, unknown> | null {
  const t = readText(p);
  if (!t) return null;
  try {
    return JSON.parse(t) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Read a string-keyed sub-object (e.g. package.json `scripts`). */
function subRecord(obj: Record<string, unknown> | null, key: string): Record<string, unknown> | null {
  const v = obj?.[key];
  return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
}

function gitTagCount(root: string): number {
  try {
    return execFileSync("git", ["tag"], { cwd: root, stdio: "pipe", encoding: "utf8", timeout: 15000 })
      .split("\n")
      .filter((l) => l.trim()).length;
  } catch {
    return 0;
  }
}

function hasWorkflowMatching(ctx: CheckCtx, re: RegExp): boolean {
  for (const base of [ctx.app, ctx.root]) {
    const wf = path.join(base, ".github", "workflows");
    if (!fs.existsSync(wf)) continue;
    try {
      for (const f of fs.readdirSync(wf)) {
        if (!/\.(ya?ml)$/.test(f)) continue;
        if (re.test(f) || re.test(readText(path.join(wf, f)))) return true;
      }
    } catch {
      /* ignore */
    }
  }
  return false;
}

// ─────────────────────── automatable criteria map ───────────────────────
// criterion id → deterministic probe. Criteria absent from this map are treated
// as manual (n/a) and excluded from the automated percentage.

const PROBES: Record<string, (ctx: CheckCtx) => ProbeResult> = {
  // Basics — project website / docs
  description_good: (c) => readText(findInRepo(c, ["README.md", "README"])).length > 100,
  interact: (c) => /download|install|contribut|bug report|feedback|pull request|issue/i.test(readText(findInRepo(c, ["README.md", "README"]))),
  contribution: (c) =>
    Boolean(findInRepo(c, ["CONTRIBUTING.md", "CONTRIBUTING.txt", "CONTRIBUTING"])) ||
    /contribut/i.test(readText(findInRepo(c, ["README.md", "README"]))),
  contribution_requirements: (c) => Boolean(findInRepo(c, ["CONTRIBUTING.md", "CONTRIBUTING.txt", "CONTRIBUTING"])),
  documentation_basics: (c) =>
    Boolean(findInRepo(c, ["README.md", "README"])) || Boolean(firstExisting(c.app, ["docs", "DOCUMENTACION_DESARROLLO"])),
  documentation_interface: (c) =>
    Boolean(firstExisting(c.app, ["docs"])) || /api|interface|endpoint/i.test(readText(findInRepo(c, ["README.md", "README"]))),

  // Basics — license
  floss_license: (c) => Boolean(findInRepo(c, ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"])),
  license_location: (c) =>
    Boolean(findInRepo(c, ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"])) ||
    /licen[cs]e/i.test(readText(findInRepo(c, ["README.md", "README"]))),

  // Basics — repo / reporting
  repo_public: (c) => fs.existsSync(path.join(c.root, ".git")),
  report_tracker: (c) =>
    Boolean(firstExisting(c.app, [".github/ISSUE_TEMPLATE.md", ".github/ISSUE_TEMPLATE"])) ||
    /issue|tracker|bug/i.test(readText(findInRepo(c, ["README.md", "README"]))),
  vulnerability_report_process: (c) => Boolean(findInRepo(c, ["SECURITY.md", "SECURITY.txt", "SECURITY"])),
  vulnerability_reports: (c) => Boolean(findInRepo(c, ["SECURITY.md", "SECURITY.txt", "SECURITY"])),

  // Quality — build & test
  build: (c) => Boolean(subRecord(readJson(findInRepo(c, ["package.json"])), "scripts")?.build),
  build_common_tools: (c) => Boolean(findInRepo(c, ["package.json"])),
  test: (c) => {
    const scripts = subRecord(readJson(findInRepo(c, ["package.json"])), "scripts");
    return Boolean(scripts?.test) && Boolean(firstExisting(c.app, ["tests", "test", "__tests__"]));
  },
  test_continuous_integration: (c) => hasWorkflowMatching(c, /.*/),
  warnings: (c) =>
    Boolean(findInRepo(c, ["eslint.config.mjs", "eslint.config.js", ".eslintrc.json", ".eslintrc.js", ".eslintrc.yml"])) ||
    Boolean(subRecord(readJson(findInRepo(c, ["package.json"])), "scripts")?.lint),
  static_analysis: (c) =>
    hasWorkflowMatching(c, /security|sast|codeql|semgrep|scan/i) ||
    Boolean(firstExisting(c.app, ["src/lib/analysis"])),

  // Quality — dependencies
  dependencies: (c) => Boolean(findInRepo(c, ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"])),
  dependency_monitoring: (c) =>
    Boolean(firstExisting(c.app, [".github/dependabot.yml", ".github/dependabot.yaml"])) ||
    Boolean(firstExisting(c.root, [".github/dependabot.yml", ".github/dependabot.yaml"])),

  // Basics — versioning / releases
  version_tags: (c) => gitTagCount(c.root) > 0,
  release_notes: (c) => Boolean(findInRepo(c, ["CHANGELOG.md", "CHANGELOG", "RELEASES.md"])),

  // Not automatable from a checkout → explicit null (manual review).
  signed_releases: () => null,
  crypto_used: () => null,
  warnings_fixed: () => null,
};

// ─────────────────────────── assessment ───────────────────────────

interface CriterionResult {
  id: string;
  tier: BadgeTier;
  majorGroup: string;
  category: string;
  result: "met" | "unmet" | "na";
}

interface TierSummary {
  met: number;
  unmet: number;
  na: number;
  total: number;
  pct: number; // 0-100 over met+unmet (na excluded)
}

function gitRoot(): string {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: process.cwd(),
      stdio: "pipe",
      encoding: "utf8",
      timeout: 15000,
    }).trim();
  } catch {
    return path.join(process.cwd(), "..");
  }
}

/** Cumulative criteria up to (and including) the given tier. */
function criteriaUpTo(all: BadgeCriterion[], tier: BadgeTier): BadgeCriterion[] {
  const allowed = TIER_ORDER.slice(0, TIER_ORDER.indexOf(tier) + 1);
  return all.filter((c) => allowed.includes(c.tier));
}

function summarizeTier(criteria: BadgeCriterion[], results: Map<string, CriterionResult>): TierSummary {
  let met = 0;
  let unmet = 0;
  let na = 0;
  for (const c of criteria) {
    const r = results.get(`${c.tier}|${c.id}`);
    if (!r) {
      na++;
      continue;
    }
    if (r.result === "met") met++;
    else if (r.result === "unmet") unmet++;
    else na++;
  }
  const decided = met + unmet;
  return { met, unmet, na, total: criteria.length, pct: decided ? (met / decided) * 100 : 0 };
}

export async function assessBadge(opts: BadgeOptions = {}): Promise<void> {
  const headlineTier: BadgeTier = opts.tier ?? "passing";
  const name = opts.name ?? `badge-${headlineTier}-${new Date().toISOString().slice(0, 19)}`;

  console.log("🏅 OpenSSF Best Practices Badge self-assessment");
  console.log("═══════════════════════════════════════════");
  console.log(`   Headline tier: ${headlineTier}`);
  console.log(`   Run name:      ${name}`);
  console.log("═══════════════════════════════════════════\n");

  const all = parseBadgeCriteria();
  if (all.length === 0) {
    console.log("⚠ No badge criteria found. Run `npm run benchmark:setup -- --source=badge` first.");
    return;
  }

  const ctx: CheckCtx = { root: gitRoot(), app: process.cwd() };
  console.log(`   Repo root: ${ctx.root}`);
  console.log(`   App dir:   ${ctx.app}\n`);

  // Probes are tier-independent, so compute each once per unique criterion id…
  const probeById = new Map<string, ProbeResult>();
  for (const c of all) {
    if (!PROBES[c.id] || c.obsolete || c.future) continue;
    if (!probeById.has(c.id)) probeById.set(c.id, PROBES[c.id](ctx));
  }
  // …then expand into per-(tier, id) results (some criteria recur across tiers).
  const results = new Map<string, CriterionResult>();
  for (const c of all) {
    if (c.obsolete || c.future) continue;
    const outcome = probeById.get(c.id);
    if (outcome === undefined) continue; // not automatable → manual review
    results.set(`${c.tier}|${c.id}`, {
      id: c.id,
      tier: c.tier,
      majorGroup: c.majorGroup,
      category: c.category,
      result: outcome === true ? "met" : outcome === false ? "unmet" : "na",
    });
  }

  // Per-tier cumulative summaries.
  const tiers: Record<BadgeTier, TierSummary> = {} as Record<BadgeTier, TierSummary>;
  for (const tier of TIER_ORDER) {
    tiers[tier] = summarizeTier(criteriaUpTo(all, tier), results);
  }

  // ── Report ──
  for (const tier of TIER_ORDER) {
    const s = tiers[tier];
    const marker = tier === headlineTier ? " ◀ headline" : "";
    console.log(`   ${tier.toUpperCase().padEnd(8)} met ${String(s.met).padStart(2)} · unmet ${String(s.unmet).padStart(2)} · manual/n-a ${String(s.na).padStart(3)} → ${s.pct.toFixed(1)}%${marker}`);
  }
  const headline = tiers[headlineTier];
  console.log(`\n   Automated ${headlineTier}-tier compliance: ${headline.pct.toFixed(1)}%`);
  console.log(`   (${headline.met} met / ${headline.met + headline.unmet} automatable; ${headline.na} criteria need manual review)`);

  // List unmet automatable criteria for the headline tier (actionable gaps).
  const unmet = [...results.values()].filter(
    (r) => r.result === "unmet" && TIER_ORDER.indexOf(r.tier) <= TIER_ORDER.indexOf(headlineTier)
  );
  if (unmet.length) {
    console.log(`\n   ✗ Unmet automatable criteria (up to ${headlineTier}):`);
    for (const u of unmet) console.log(`     - [${u.tier}/${u.majorGroup}] ${u.id} (${u.category})`);
  }

  // ── Persist (assessment run) ──
  const byCategory: Record<string, number> = {};
  for (const tier of TIER_ORDER) byCategory[tier] = Number(tiers[tier].pct.toFixed(2));

  const run = await prisma.benchmarkRun.create({
    data: {
      name,
      source: "best-practices-badge",
      kind: "assessment",
      totalCases: results.size,
      score: tiers[headlineTier].pct / 100, // normalized 0-1 headline
      byCategory: byCategory as object,
      metrics: {
        standard: "openssf-best-practices-badge",
        headlineTier,
        repoRoot: ctx.root,
        tiers: {
          passing: tiers.passing,
          silver: tiers.silver,
          gold: tiers.gold,
        },
        criteriaResults: [...results.values()],
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
        source: "best-practices-badge",
        kind: "assessment",
        headlineTier,
        normalized: tiers[headlineTier].pct / 100,
        tiers,
        criteriaResults: [...results.values()],
      },
      null,
      2
    )
  );
  console.log(`💾 Report: ${reportPath}`);
}

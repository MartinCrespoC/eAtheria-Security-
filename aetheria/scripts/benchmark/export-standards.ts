/**
 * Exports the industry-standards documentation data:
 *  - copies the latest JSON report per source into industry-standards/evidence/
 *  - regenerates industry-standards/SCORES.md (snapshot of latest BenchmarkRuns)
 *  - regenerates industry-standards/07-bestpractices-criteria.md: the FULL
 *    official criteria checklist (parsed from vendor/fp/best-practices-badge
 *    criteria.yml + en.yml descriptions) merged with our latest self-assessment
 *    results (BenchmarkRun.metrics.criteriaResults)
 *
 * Usage: TMPDIR=/tmp npx tsx scripts/benchmark/export-standards.ts
 */
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../src/lib/db";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const yaml = require("js-yaml");

const DOCS_DIR = path.join(process.cwd(), "..", "industry-standards");
const EVIDENCE_DIR = path.join(DOCS_DIR, "evidence");
const REPORTS_DIR = path.join(process.cwd(), "scripts", "benchmark", "reports");
const BADGE_REPO = path.join(process.cwd(), "vendor", "fp", "best-practices-badge");

const TIER_NAMES = ["passing", "silver", "gold"] as const;

interface OfficialCriterion {
  id: string;
  tier: string;
  majorGroup: string;
  minorGroup: string;
  category: string; // MUST | SHOULD | SUGGESTED
  description: string;
  details: string;
}

function loadOfficialCriteria(): OfficialCriterion[] {
  const criteriaPath = path.join(BADGE_REPO, "criteria", "criteria.yml");
  const localePath = path.join(BADGE_REPO, "config", "locales", "en.yml");
  if (!fs.existsSync(criteriaPath) || !fs.existsSync(localePath)) return [];

  // criteria.yml uses Ruby `!!omap` tags; stripping them leaves plain sequences
  // of single-key maps, which is exactly the same semantics.
  const critText = fs.readFileSync(criteriaPath, "utf8").replace(/ !!omap/g, "");
  const critDoc = yaml.load(critText) as Array<Record<string, unknown[]>>;
  const localeDoc = yaml.load(fs.readFileSync(localePath, "utf8")) as {
    en?: { criteria?: Record<string, Record<string, { description?: string; details?: string }>> };
  };
  const localeCriteria = localeDoc?.en?.criteria ?? {};

  const out: OfficialCriterion[] = [];
  for (const tierObj of critDoc) {
    const tierIdx = Object.keys(tierObj)[0];
    const tier = TIER_NAMES[Number(tierIdx)] ?? tierIdx;
    const groups = (tierObj[tierIdx] as Array<Record<string, unknown[]>>) ?? [];
    const localeTier = localeCriteria[tierIdx] ?? {};
    for (const groupObj of groups) {
      const majorGroup = Object.keys(groupObj)[0];
      for (const minorObj of groupObj[majorGroup] as Array<Record<string, unknown[]>>) {
        const minorGroup = Object.keys(minorObj)[0];
        for (const critObj of minorObj[minorGroup] as Array<Record<string, Record<string, string>>>) {
          const id = Object.keys(critObj)[0];
          const body = critObj[id] ?? {};
          const loc = localeTier[id] ?? {};
          out.push({
            id,
            tier,
            majorGroup,
            minorGroup,
            category: (body.category ?? "SUGGESTED").toUpperCase(),
            description: (loc.description ?? "").replace(/\s+/g, " ").trim(),
            details: (loc.details ?? "").replace(/\s+/g, " ").trim(),
          });
        }
      }
    }
  }
  return out;
}

function pct(x: number | null | undefined): string {
  return `${(((x ?? 0) as number) * 100).toFixed(1).replace(/\.0$/, "")}%`;
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();

async function main() {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  const sources = ["curated", "owasp-full", "wstg", "juliet", "cve-benchmark", "scorecard", "best-practices-badge"];
  const latest: Record<string, Awaited<ReturnType<typeof prisma.benchmarkRun.findFirst>>> = {};
  for (const s of sources) {
    latest[s] = await prisma.benchmarkRun.findFirst({
      where: { source: { contains: s } },
      orderBy: { createdAt: "desc" },
    });
  }

  // ── 1. copy latest evidence reports ──
  for (const [s, run] of Object.entries(latest)) {
    if (!run) continue;
    const src = path.join(REPORTS_DIR, `${run.id}.json`);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(EVIDENCE_DIR, `${s}-${run.id}.json`));
      console.log(`   ${s} → evidence/${s}-${run.id}.json`);
    }
  }

  // ── 2. SCORES.md snapshot ──
  const rows: string[] = [];
  for (const [s, run] of Object.entries(latest)) {
    if (!run) {
      rows.push(`| ${s} | — | — | — | — | — |`);
      continue;
    }
    rows.push(
      `| ${esc(s)} | ${esc(run.name)} | ${run.createdAt.toISOString().slice(0, 19)}Z | ${run.totalCases} | score ${pct(run.score)} | TPR ${pct(run.tpr)} · FPR ${pct(run.fpr)} |`
    );
  }
  fs.writeFileSync(
    path.join(DOCS_DIR, "SCORES.md"),
    `# Scores Snapshot (auto-generated)

> Regenerate: \`TMPDIR=/tmp npx tsx scripts/benchmark/export-standards.ts\` (from \`aetheria/\`).
> Source of truth: \`BenchmarkRun\` rows in the platform database.

| Source | Run name | Date (UTC) | Cases | Headline | Detail |
|---|---|---|---|---|---|
${rows.join("\n")}

Evidence JSON for each row lives in \`evidence/\` (copied from \`aetheria/scripts/benchmark/reports/\`).

## Glosario

- **Cases**: número total de casos evaluados por el benchmark (para CVE son 440: 220 CVEs × commit vulnerable + commit parcheado).
- **TP (True Positive)**: casos positivos reales que la herramienta detectó correctamente.
- **FP (False Positive)**: casos negativos que la herramienta marcó por error.
- **TN (True Negative)**: casos negativos reales que la herramienta dejó sin marcar.
- **FN (False Negative)**: casos positivos reales que la herramienta no detectó.
- **TPR (True Positive Rate / Recall)**: \`TP / (TP + FN)\` — cobertura de vulnerabilidades reales.
- **FPR (False Positive Rate)**: \`FP / (FP + TN)\` — tasa de alarmas falsas.
- **Score**: \`TPR − FPR\` — métrica neta del benchmark; penaliza tanto perder vulnerabilidades como reportar falsas.
- **Run name**: identificador del run en la tabla \`BenchmarkRun\` del core.
- **Evidence JSON**: reporte con el detalle de cada caso, confusión y snippets; sirve para auditar un score.
`
  );

  // ── 3. 07-bestpractices-criteria.md ──
  const badge = latest["best-practices-badge"];
  const metrics = (badge?.metrics ?? {}) as {
    criteriaResults?: Array<{ id: string; tier: string; majorGroup?: string; category?: string; result: string }>;
    tiers?: Record<string, { met: number; unmet: number; na: number; total: number; pct: number }>;
  };
  const resultById = new Map<string, string>();
  for (const r of metrics.criteriaResults ?? []) resultById.set(r.id, r.result);

  const official = loadOfficialCriteria();

  const statusOf = (c: OfficialCriterion): string => {
    const r = resultById.get(c.id);
    if (r === "met") return "✅ MET";
    if (r === "unmet") return "❌ UNMET";
    return "🖐 MANUAL";
  };

  let md = `# OpenSSF Best Practices — Full Criteria Checklist (auto-generated)

> Regenerate: \`TMPDIR=/tmp npx tsx scripts/benchmark/export-standards.ts\`.
> Latest self-assessment run: \`${badge?.name ?? "—"}\` (${badge?.createdAt.toISOString() ?? "—"}).
> Official criteria: \`ossf/best-practices-badge\` criteria.yml + en.yml (vendored at \`aetheria/vendor/fp/best-practices-badge/\`).
> Total official criteria: **${official.length}** (passing/silver/gold cumulative).

## How to read this

- **✅ MET** — verified automatically by our probe (\`scripts/benchmark/assess/badge.ts\`) against this repository.
- **❌ UNMET** — automatable and currently failing (must fix before registering).
- **🖐 MANUAL** — not verifiable from the repo alone; answer it on bestpractices.dev
  with the justification suggested in \`05-openssf-best-practices.md\` §3.

`;
  for (const tier of TIER_NAMES) {
    const list = official.filter((c) => c.tier === tier);
    if (!list.length) continue;
    const t = metrics.tiers?.[tier];
    md += `\n## Tier: ${tier.toUpperCase()}${t ? ` — our assessment: met ${t.met} · unmet ${t.unmet} · manual/n-a ${t.na} → **${t.pct}% automatable**` : ""}\n`;
    let lastGroup = "";
    let tableOpen = false;
    for (const c of list) {
      if (c.majorGroup !== lastGroup) {
        if (tableOpen) md += "\n";
        md += `\n### ${c.majorGroup}\n\n| Criterion | Status | Level | Requirement (official text) |\n|---|---|---|---|\n`;
        lastGroup = c.majorGroup;
        tableOpen = true;
      }
      md += `| \`${c.id}\` | ${statusOf(c)} | ${c.category} | ${esc(c.description || c.minorGroup)} |\n`;
    }
    md += "\n";
  }
  fs.writeFileSync(path.join(DOCS_DIR, "07-bestpractices-criteria.md"), md);

  console.log("    SCORES.md, 07-bestpractices-criteria.md regenerated");
  console.log(`    criteria in checklist: ${official.length}`);
}

main()
  .catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

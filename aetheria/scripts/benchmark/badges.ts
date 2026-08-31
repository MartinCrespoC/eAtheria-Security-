/**
 * Benchmark badge generator — rewrites the README badge block from the LATEST
 * persisted `BenchmarkRun` rows, so the shields always reflect real measured
 * runs (never hand-edited numbers).
 *
 * Usage:
 *   TMPDIR=/tmp npx tsx scripts/benchmark/badges.ts
 *
 * Works with a PRIVATE repo: badges are shields.io static images (public CDN)
 * plus the GitHub Actions workflow badge (visible to repo members). The
 * bestpractices.dev / api.securityscorecards.dev hosted badges require a
 * public repo and are intentionally NOT included while the repo is private.
 */
import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import { prisma } from "../../src/lib/db";

const START = "<!-- BENCHMARK-BADGES:START -->";
const END = "<!-- BENCHMARK-BADGES:END -->";

function shield(label: string, message: string, color: string, logo?: string): string {
  const l = label.replace(/-/g, "--").replace(/_/g, "__").replace(/ /g, "_");
  const m = message.replace(/-/g, "--").replace(/_/g, "__").replace(/ /g, "_").replace(/%/g, "%25");
  const logoPart = logo ? `?logo=${logo}&logoColor=white` : "";
  return `![${label} ${message}](https://img.shields.io/badge/${l}-${m}-${color}${logoPart})`;
}

function pct(x: number | null): string {
  return `${((x ?? 0) * 100).toFixed(1).replace(/\.0$/, "")}%`;
}

async function latestRun(source: string) {
  return prisma.benchmarkRun.findFirst({
    where: { source: { contains: source } },
    orderBy: { createdAt: "desc" },
  });
}

async function main() {
  const repoUrl = execFileSync("git", ["config", "--get", "remote.origin.url"], {
    cwd: path.join(process.cwd(), ".."),
    encoding: "utf8",
    timeout: 15000,
  }).trim().replace(/\.git$/, "");

  const [owasp, curated, cve, scorecard, badge] = await Promise.all([
    latestRun("owasp-full"),
    latestRun("curated"),
    latestRun("cve-benchmark"),
    prisma.benchmarkRun.findFirst({ where: { source: "scorecard" }, orderBy: { createdAt: "desc" } }),
    prisma.benchmarkRun.findFirst({ where: { source: "best-practices-badge" }, orderBy: { createdAt: "desc" } }),
  ]);

  const lines: string[] = [];
  // CI status (visible to repo members while the repo is private).
  lines.push(`[![Security Scan](${repoUrl}/actions/workflows/security-scan.yml/badge.svg?branch=main)](${repoUrl}/actions/workflows/security-scan.yml)`);
  if (owasp) {
    const ok = (owasp.score ?? 0) >= 0.999;
    lines.push(shield("OWASP Benchmark", `${pct(owasp.score)} TPR-FPR`, ok ? "brightgreen" : "orange", "owasp"));
  }
  if (curated) {
    const ok = (curated.score ?? 0) >= 0.999;
    lines.push(shield("WSTG + Juliet + curated", pct(curated.score), ok ? "brightgreen" : "orange"));
  }
  if (cve) {
    lines.push(shield("OpenSSF CVE Benchmark", `TPR ${pct(cve.tpr)} · FPR ${pct(cve.fpr)}`, (cve.tpr ?? 0) >= 0.9 ? "brightgreen" : "orange"));
  }
  if (badge) {
    const ok = (badge.score ?? 0) >= 0.999;
    lines.push(shield("OpenSSF Best Practices", `passing ${pct(badge.score)}`, ok ? "brightgreen" : "yellow"));
  }
  if (scorecard) {
    const ten = ((scorecard.score ?? 0) * 10).toFixed(1).replace(/\.0$/, "");
    lines.push(shield("OpenSSF Scorecard", `${ten}/10`, (scorecard.score ?? 0) >= 0.9 ? "brightgreen" : "yellow"));
  }

  const block = `${START}\n${lines.join("\n")}\n${END}`;

  const readmePath = path.join(process.cwd(), "..", "README.md");
  const readme = fs.readFileSync(readmePath, "utf8");
  const re = new RegExp(`${START}[\\s\\S]*?${END}`);
  let next: string;
  if (re.test(readme)) {
    next = readme.replace(re, block);
  } else {
    // Insert after the first heading line.
    const linesR = readme.split("\n");
    const hIdx = linesR.findIndex((l) => l.startsWith("#"));
    linesR.splice(hIdx + 1, 0, "", block);
    next = linesR.join("\n");
  }
  fs.writeFileSync(readmePath, next);

  console.log("🏅 README badge block updated from latest BenchmarkRun rows:");
  for (const l of lines) console.log("   ", l.slice(0, 120));
}

main()
  .catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

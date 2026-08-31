/**
 * Self-scan: run AETHERIA's own detection engines over the platform's
 * source tree (aetheria/src) and report where we stand.
 *
 * Read-only: rules are loaded from the DB (SELECT only), no writes.
 *
 * Usage:  npx tsx scripts/benchmark/self-scan.ts [--with-ai] [--max-findings N]
 */
import * as fs from "fs";
import * as path from "path";
import { detectInCode, type DetectionOutcome } from "./detect";
import { prisma } from "../../src/lib/db";

const SRC_ROOT = path.resolve(__dirname, "../../src");
const EXCLUDE = /(__tests__|\.test\.|\.spec\.|\.d\.ts$|node_modules)/;
const EXT = new Set([".ts", ".tsx", ".js", ".jsx"]);

const withAi = process.argv.includes("--with-ai");
const maxArg = process.argv.find((a) => a.startsWith("--max-findings="));
const MAX_SHOW = maxArg ? Number(maxArg.split("=")[1]) : 40;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && !entry.name.startsWith(".")) out.push(...walk(abs));
    } else if (EXT.has(path.extname(entry.name)) && !EXCLUDE.test(abs)) {
      out.push(abs);
    }
  }
  return out;
}

function langOf(file: string): string {
  const ext = path.extname(file);
  return ext === ".ts" || ext === ".tsx" ? "typescript" : "javascript";
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

async function main() {
  const files = walk(SRC_ROOT);
  console.log(`🛡️  AETHERIA self-scan — ${files.length} files under src/`);
  console.log(`   AI triage: ${withAi ? "ON" : "OFF (deterministic + FP detector only)"}\n`);

  const all: DetectionOutcome[] = [];
  let done = 0;
  const CONCURRENCY = 8;
  let cursor = 0;
  async function worker() {
    while (cursor < files.length) {
      const file = files[cursor++];
      const rel = path.relative(SRC_ROOT, file);
      try {
        const outcomes = await detectInCode({
          fileContent: fs.readFileSync(file, "utf8"),
          filePath: rel,
          language: langOf(file),
          scanLevel: "STATIC",
          withAi,
        });
        all.push(...outcomes);
      } catch (err) {
        console.warn(`   ⚠ ${rel}: ${err instanceof Error ? err.message : err}`);
      }
      if (++done % 100 === 0) console.log(`   … ${done}/${files.length} files`);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));

  const kept = all.filter((o) => o.kept);
  const fps = all.filter((o) => !o.kept);

  const byCwe = new Map<string, number>();
  const bySev = new Map<string, number>();
  for (const o of kept) {
    byCwe.set(o.cweId ?? "-", (byCwe.get(o.cweId ?? "-") ?? 0) + 1);
    bySev.set(o.severity, (bySev.get(o.severity) ?? 0) + 1);
  }

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("📊 RESULTADOS");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`Archivos:           ${files.length}`);
  console.log(`Hallazgos crudos:   ${all.length}`);
  console.log(`Reportados (kept):  ${kept.length}`);
  console.log(`Descartados (FP):   ${fps.length}`);

  console.log("\nPor severidad (kept):");
  for (const sev of SEV_ORDER) {
    const n = bySev.get(sev) ?? 0;
    if (n) console.log(`  ${sev.padEnd(9)} ${n}`);
  }

  console.log("\nPor CWE (kept, top 15):");
  [...byCwe.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)
    .forEach(([cwe, n]) => console.log(`  ${cwe.padEnd(10)} ${n}`));

  const critHigh = kept
    .filter((o) => o.severity === "CRITICAL" || o.severity === "HIGH")
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  console.log(`\n🔴 CRITICAL/HIGH reportados (mostrando ${Math.min(MAX_SHOW, critHigh.length)} de ${critHigh.length}):`);
  for (const o of critHigh.slice(0, MAX_SHOW)) {
    console.log(`  [${o.severity}] ${o.cweId} ${o.title}`);
    console.log(`      ${o.file}:${o.line}`);
  }

  if (fps.length) {
    console.log("\nTop razones de descarte (FP):");
    const reasons = new Map<string, number>();
    for (const o of fps) {
      const r = (o.fpReason ?? "sin razón").slice(0, 80);
      reasons.set(r, (reasons.get(r) ?? 0) + 1);
    }
    [...reasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
      .forEach(([r, n]) => console.log(`  ${String(n).padStart(4)}  ${r}`));
  }

  await prisma.$disconnect();
}

main().catch(async (e) => {
  console.error(e);
  await prisma.$disconnect();
  process.exit(1);
});

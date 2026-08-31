/**
 * FP Knowledge System — orchestrator.
 *
 * Runs a set of source adapters: fetch upstream data → parse → validate →
 * idempotently upsert into the DB (FalsePositivePattern + CweKnowledge) and
 * record provenance in FpKnowledgeSource. Mirrors the sync-bughunter pattern
 * (clone into vendor/, sync lib in src/lib/knowledge, npm-script entrypoint).
 */
import { execFileSync } from "child_process";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { prisma } from "@/lib/db";
import type {
  FpSourceAdapter,
  NormalizedCweKnowledge,
  NormalizedFpPattern,
  SyncOptions,
  SyncStats,
} from "./types";

export const VENDOR_ROOT = path.join(process.cwd(), "vendor", "fp");
const UPSERT_CHUNK = 200;

/** Clone (shallow) or pull a git repo into `dir`. Non-fatal on pull failure. */
export function ensureGitRepo(repoUrl: string, dir: string): void {
  if (fs.existsSync(path.join(dir, ".git"))) {
    try {
      execFileSync("git", ["pull", "--ff-only"], { cwd: dir, stdio: "pipe", timeout: 120000 });
    } catch {
      console.warn(`   ⚠ git pull failed for ${dir}, using existing clone`);
    }
    return;
  }
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  execFileSync("git", ["clone", "--depth", "1", repoUrl, dir], { stdio: "pipe", timeout: 300000 });
}

/** Download a URL to `cachePath` (only if missing or force). Returns the path. */
export async function ensureHttpFile(url: string, cachePath: string, force = false): Promise<string> {
  if (!force && fs.existsSync(cachePath)) return cachePath;
  fs.mkdirSync(path.dirname(cachePath), { recursive: true });
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(cachePath, buf);
  return cachePath;
}

/** True if `pattern` compiles as a JS RegExp. */
export function isValidRegex(pattern: string): boolean {
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function dedupe<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

/** Idempotently upsert normalized patterns keyed by (source, sourceRuleId). */
async function upsertPatterns(patterns: NormalizedFpPattern[]): Promise<{ created: number; updated: number; skipped: number }> {
  let created = 0;
  let updated = 0;
  let skipped = 0;

  // Validate + normalize, dropping invalid regexes.
  const valid: NormalizedFpPattern[] = [];
  for (const p of patterns) {
    if (!p.pattern || !isValidRegex(p.pattern)) {
      skipped++;
      continue;
    }
    if (!p.sourceRuleId) {
      skipped++;
      continue;
    }
    valid.push({ ...p, cweIds: dedupe(p.cweIds) });
  }

  for (let i = 0; i < valid.length; i += UPSERT_CHUNK) {
    const chunk = valid.slice(i, i + UPSERT_CHUNK);
    const results = await prisma.$transaction(
      chunk.map((p) =>
        prisma.falsePositivePattern.upsert({
          where: { source_sourceRuleId: { source: p.source, sourceRuleId: p.sourceRuleId } },
          update: {
            language: p.language,
            pattern: p.pattern,
            description: p.description,
            reason: p.reason,
            context: p.context ?? null,
            cweIds: p.cweIds,
            examples: p.examples ?? [],
            confidence: p.confidence,
            category: p.category ?? null,
            isActive: true,
          },
          create: {
            language: p.language,
            pattern: p.pattern,
            description: p.description,
            reason: p.reason,
            context: p.context ?? null,
            cweIds: p.cweIds,
            examples: p.examples ?? [],
            source: p.source,
            sourceRuleId: p.sourceRuleId,
            confidence: p.confidence,
            category: p.category ?? null,
            isActive: true,
          },
        })
      )
    );
    // upsert returns the row; distinguish create vs update by createdAt==updatedAt is unreliable,
    // so count via a lightweight heuristic: if updatedAt differs from createdAt it was updated.
    for (const r of results) {
      if (r.createdAt.getTime() === r.updatedAt.getTime()) created++;
      else updated++;
    }
  }

  return { created, updated, skipped };
}

/** Upsert CWE knowledge, union-ing array fields with any existing record. */
async function upsertCweKnowledge(items: NormalizedCweKnowledge[]): Promise<number> {
  let count = 0;
  for (const k of items) {
    const existing = await prisma.cweKnowledge.findUnique({ where: { cweId: k.cweId } });
    const commonFalsePositives = dedupe([
      ...((existing?.commonFalsePositives as string[] | null) ?? []),
      ...k.commonFalsePositives,
    ]);
    const detectionGuidance = {
      methods: dedupe([
        ...(((existing?.detectionGuidance as { methods?: string[] } | null)?.methods) ?? []),
        ...k.detectionMethods,
      ]),
      doNotFlag: dedupe([
        ...(((existing?.detectionGuidance as { doNotFlag?: string[] } | null)?.doNotFlag) ?? []),
        ...k.doNotFlag,
      ]),
    };
    const mitigations = dedupe([
      ...((existing?.mitigations as string[] | null) ?? []),
      ...k.mitigations,
    ]);
    await prisma.cweKnowledge.upsert({
      where: { cweId: k.cweId },
      update: {
        name: k.name,
        category: k.category ?? existing?.category ?? null,
        description: k.description ?? existing?.description ?? null,
        extendedDescription: k.extendedDescription ?? existing?.extendedDescription ?? null,
        commonFalsePositives,
        detectionGuidance,
        mitigations,
        owaspTop10: k.owaspTop10 ?? existing?.owaspTop10 ?? null,
        mitreTop25Rank: k.mitreTop25Rank ?? existing?.mitreTop25Rank ?? null,
        isActive: true,
      },
      create: {
        cweId: k.cweId,
        name: k.name,
        category: k.category ?? null,
        description: k.description ?? null,
        extendedDescription: k.extendedDescription ?? null,
        commonFalsePositives,
        detectionGuidance,
        mitigations,
        owaspTop10: k.owaspTop10 ?? null,
        mitreTop25Rank: k.mitreTop25Rank ?? null,
        source: k.source,
        isActive: true,
      },
    });
    count++;
  }
  return count;
}

/** Run all (or selected) adapters and persist results. */
export async function syncFpKnowledge(adapters: FpSourceAdapter[], options: SyncOptions = {}): Promise<SyncStats[]> {
  const selected = options.sources?.length
    ? adapters.filter((a) => options.sources!.includes(a.id))
    : adapters;

  const allStats: SyncStats[] = [];

  for (const adapter of selected) {
    const start = Date.now();
    const stats: SyncStats = {
      source: adapter.id,
      parsed: 0,
      patternsCreated: 0,
      patternsUpdated: 0,
      patternsSkipped: 0,
      cweUpserted: 0,
      benchmarkCases: 0,
      errors: [],
      durationMs: 0,
    };

    console.log(`\n🔄 [${adapter.id}] ${adapter.name}`);
    try {
      await prisma.fpKnowledgeSource.upsert({
        where: { source: adapter.id },
        update: { status: "syncing" },
        create: { source: adapter.id, status: "syncing" },
      });

      await adapter.fetch();

      const patterns = await adapter.parsePatterns();
      const cwe = (await adapter.parseCweKnowledge?.()) ?? [];
      stats.parsed = patterns.length + cwe.length;

      // Incremental sync: skip persist if content unchanged (unless forced).
      const checksum = sha256(JSON.stringify({ p: patterns, c: cwe }));
      const prev = await prisma.fpKnowledgeSource.findUnique({ where: { source: adapter.id } });
      if (!options.force && prev?.checksum === checksum && prev.patternCount > 0) {
        console.log(`   ✓ Sin cambios (checksum igual) — omitiendo upsert`);
        await prisma.fpKnowledgeSource.update({
          where: { source: adapter.id },
          data: { status: "ok", lastSyncAt: new Date() },
        });
        stats.durationMs = Date.now() - start;
        allStats.push(stats);
        continue;
      }

      const pr = await upsertPatterns(patterns);
      stats.patternsCreated = pr.created;
      stats.patternsUpdated = pr.updated;
      stats.patternsSkipped = pr.skipped;
      stats.cweUpserted = await upsertCweKnowledge(cwe);

      await prisma.fpKnowledgeSource.update({
        where: { source: adapter.id },
        data: {
          status: "ok",
          checksum,
          patternCount: patterns.length,
          lastSyncAt: new Date(),
          meta: { cweKnowledge: cwe.length, skipped: pr.skipped },
        },
      });

      console.log(
        `   ✅ patterns +${pr.created} / ~${pr.updated} (skip ${pr.skipped}), cwe ${cwe.length}`
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      stats.errors.push(msg);
      console.error(`   ✗ [${adapter.id}] error: ${msg}`);
      await prisma.fpKnowledgeSource
        .update({ where: { source: adapter.id }, data: { status: "error" } })
        .catch(() => undefined);
    }

    stats.durationMs = Date.now() - start;
    allStats.push(stats);
  }

  return allStats;
}

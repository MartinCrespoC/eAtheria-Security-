/**
 * BugHunter Knowledge Sync Service
 * Reads parsed SKILL.md files and upserts them into the HuntSkill + HuntSkillCwe DB tables.
 * Idempotent: can be run repeatedly without creating duplicates.
 */

import { prisma } from "@/lib/db";
import { parseSkillMarkdown, type ParsedSkill } from "./skill-parser";
import { getCweMappingsForSkill, inferCwesFromDescription } from "./cwe-mapper";
import * as fs from "fs";
import * as path from "path";

export interface SyncStats {
  created: number;
  updated: number;
  skipped: number;
  errors: string[];
  total: number;
}

/**
 * Sync all BugHunter skills from the vendor clone into the database.
 * @param vendorDir - Path to the cloned BugHunter repo (default: vendor/bughunter)
 * @param options.force - If true, update even if lastSyncedAt is recent
 */
export async function syncHuntSkills(options?: {
  vendorDir?: string;
  force?: boolean;
}): Promise<SyncStats> {
  const vendorDir = options?.vendorDir || path.join(process.cwd(), "vendor", "bughunter");
  const skillsDir = path.join(vendorDir, "skills");

  const stats: SyncStats = { created: 0, updated: 0, skipped: 0, errors: [], total: 0 };

  // Check if vendor dir exists
  if (!fs.existsSync(skillsDir)) {
    stats.errors.push(`Skills directory not found: ${skillsDir}. Run: git clone --depth 1 https://github.com/elementalsouls/Claude-BugHunter.git vendor/bughunter`);
    return stats;
  }

  // Walk skills directory: each subdirectory contains a SKILL.md
  const entries = fs.readdirSync(skillsDir, { withFileTypes: true });
  const skillDirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);

  stats.total = skillDirs.length;
  console.log(`[SYNC] Found ${skillDirs.length} skill directories in ${skillsDir}`);

  for (const dir of skillDirs) {
    const skillFile = path.join(skillsDir, dir, "SKILL.md");
    if (!fs.existsSync(skillFile)) {
      stats.skipped++;
      continue;
    }

    try {
      const raw = fs.readFileSync(skillFile, "utf-8");
      const slug = dir; // directory name = skill slug
      const parsed = parseSkillMarkdown(raw, slug);

      await upsertSkill(parsed);
      stats.created++; // upsert counts as created or updated
    } catch (err) {
      const msg = `Error parsing ${dir}: ${err instanceof Error ? err.message : "Unknown"}`;
      stats.errors.push(msg);
      console.error(`[SYNC] ${msg}`);
    }
  }

  // Also check for commands/ directory skills (some skills may be there)
  const commandsDir = path.join(vendorDir, "commands");
  if (fs.existsSync(commandsDir)) {
    const cmdEntries = fs.readdirSync(commandsDir, { withFileTypes: true });
    const cmdDirs = cmdEntries.filter((e) => e.isDirectory()).map((e) => e.name);
    for (const dir of cmdDirs) {
      const skillFile = path.join(commandsDir, dir, "SKILL.md");
      if (!fs.existsSync(skillFile)) continue;
      try {
        const raw = fs.readFileSync(skillFile, "utf-8");
        const parsed = parseSkillMarkdown(raw, dir);
        await upsertSkill(parsed);
        stats.created++;
        stats.total++;
      } catch {
        // Commands are optional, skip errors
      }
    }
  }

  console.log(`[SYNC] Complete: ${stats.created} upserted, ${stats.skipped} skipped, ${stats.errors.length} errors`);
  return stats;
}

/**
 * Upsert a single parsed skill into the database.
 */
async function upsertSkill(parsed: ParsedSkill): Promise<void> {
  // Get CWE mappings (curated + inferred fallback)
  let cweMappings = getCweMappingsForSkill(parsed.slug);
  if (cweMappings.length === 0 && parsed.description) {
    cweMappings = inferCwesFromDescription(parsed.description);
  }

  const cweIds = cweMappings.map((m) => m.cweId);

  // Upsert the skill
  const skill = await prisma.huntSkill.upsert({
    where: { slug: parsed.slug },
    update: {
      name: parsed.name,
      category: parsed.category,
      description: parsed.description.slice(0, 2000),
      reportCount: parsed.reportCount,
      sources: parsed.sources,
      cweIds,
      rootCauses: parsed.rootCauses,
      attackSignals: parsed.attackSignals,
      detectionPatterns: parsed.detectionPatterns,
      bypassTechniques: parsed.bypassTechniques,
      validationGate: parsed.validationGate,
      impactExamples: parsed.impactExamples,
      chains: parsed.chains,
      methodology: parsed.methodology,
      frameworks: parsed.frameworks,
      languages: parsed.languages,
      lastSyncedAt: new Date(),
    },
    create: {
      slug: parsed.slug,
      name: parsed.name,
      category: parsed.category,
      description: parsed.description.slice(0, 2000),
      reportCount: parsed.reportCount,
      sources: parsed.sources,
      cweIds,
      rootCauses: parsed.rootCauses,
      attackSignals: parsed.attackSignals,
      detectionPatterns: parsed.detectionPatterns,
      bypassTechniques: parsed.bypassTechniques,
      validationGate: parsed.validationGate,
      impactExamples: parsed.impactExamples,
      chains: parsed.chains,
      methodology: parsed.methodology,
      frameworks: parsed.frameworks,
      languages: parsed.languages,
      lastSyncedAt: new Date(),
    },
  });

  // Upsert CWE mappings
  for (const mapping of cweMappings) {
    await prisma.huntSkillCwe.upsert({
      where: {
        skillId_cweId: { skillId: skill.id, cweId: mapping.cweId },
      },
      update: { relevance: mapping.relevance },
      create: {
        skillId: skill.id,
        cweId: mapping.cweId,
        relevance: mapping.relevance,
      },
    });
  }
}

/**
 * Sync a single skill from raw markdown content (for admin API / on-demand sync).
 */
export async function syncSingleSkill(slug: string, rawMarkdown: string): Promise<void> {
  const parsed = parseSkillMarkdown(rawMarkdown, slug);
  await upsertSkill(parsed);
}

/**
 * BugHunter Knowledge Seed Script
 * Populates the HuntSkill knowledge base from the vendored snapshot in
 * prisma/seed-data/bughunter-*.json (generated from the Claude-BugHunter
 * sync). Runs offline — no git clone or network needed, so the container
 * entrypoint can execute it on every boot.
 *
 * Run: npx tsx scripts/seed-bughunter.ts
 *
 * To refresh the snapshot: run scripts/sync-bughunter.ts against a database,
 * then re-export:
 *   hunt_skills      -> prisma/seed-data/bughunter-skills.json
 *   hunt_skill_cwe   -> prisma/seed-data/bughunter-cwe-mappings.json
 *
 * Tables populated: HuntSkill, HuntSkillCwe (idempotent upserts).
 */
import { readFileSync } from "fs";
import path from "path";
import { PrismaClient, Prisma } from "@prisma/client";

const prisma = new PrismaClient();

interface SkillRow {
  slug: string;
  name: string;
  category: string;
  description: string;
  reportCount: number;
  sources: Prisma.InputJsonValue | null;
  cweIds: Prisma.InputJsonValue;
  rootCauses: Prisma.InputJsonValue | null;
  attackSignals: Prisma.InputJsonValue | null;
  detectionPatterns: Prisma.InputJsonValue | null;
  bypassTechniques: Prisma.InputJsonValue | null;
  validationGate: Prisma.InputJsonValue | null;
  impactExamples: Prisma.InputJsonValue | null;
  chains: Prisma.InputJsonValue | null;
  methodology: string | null;
  frameworks: Prisma.InputJsonValue;
  languages: Prisma.InputJsonValue;
}

interface CweMappingRow {
  skillSlug: string;
  cweId: string;
  relevance: string;
}

function loadJson<T>(file: string): T[] {
  const p = path.join(__dirname, "..", "prisma", "seed-data", file);
  return JSON.parse(readFileSync(p, "utf-8")) as T[];
}

async function main() {
  const skills = loadJson<SkillRow>("bughunter-skills.json");
  const mappings = loadJson<CweMappingRow>("bughunter-cwe-mappings.json");

  console.log(`[SEED-BUGHUNTER] Seeding ${skills.length} hunt skills...`);
  const idBySlug = new Map<string, string>();

  for (const s of skills) {
    const data = {
      name: s.name,
      category: s.category,
      description: s.description,
      reportCount: s.reportCount ?? 0,
      sources: s.sources ?? Prisma.JsonNull,
      cweIds: s.cweIds ?? [],
      rootCauses: s.rootCauses ?? Prisma.JsonNull,
      attackSignals: s.attackSignals ?? Prisma.JsonNull,
      detectionPatterns: s.detectionPatterns ?? Prisma.JsonNull,
      bypassTechniques: s.bypassTechniques ?? Prisma.JsonNull,
      validationGate: s.validationGate ?? Prisma.JsonNull,
      impactExamples: s.impactExamples ?? Prisma.JsonNull,
      chains: s.chains ?? Prisma.JsonNull,
      methodology: s.methodology,
      frameworks: s.frameworks ?? [],
      languages: s.languages ?? [],
      isActive: true,
      lastSyncedAt: new Date(),
    };
    const row = await prisma.huntSkill.upsert({
      where: { slug: s.slug },
      update: data,
      create: { slug: s.slug, ...data },
      select: { id: true },
    });
    idBySlug.set(s.slug, row.id);
  }

  console.log(`[SEED-BUGHUNTER] Seeding ${mappings.length} CWE mappings...`);
  let mapped = 0;
  for (const m of mappings) {
    const skillId = idBySlug.get(m.skillSlug);
    if (!skillId) continue;
    await prisma.huntSkillCwe.upsert({
      where: { skillId_cweId: { skillId, cweId: m.cweId } },
      update: { relevance: m.relevance },
      create: { skillId, cweId: m.cweId, relevance: m.relevance },
    });
    mapped++;
  }

  console.log(`[SEED-BUGHUNTER] ✅ Done: ${skills.length} skills, ${mapped} CWE mappings`);
}

main()
  .catch((e) => {
    console.error("[SEED-BUGHUNTER] Error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

/**
 * Knowledge Service Layer
 * Provides query APIs for BugHunter knowledge stored in the DB.
 * All functions respect isActive: true.
 */

import { prisma } from "@/lib/db";
import type { HuntSkill, HuntSkillCwe, VulnerabilityCatalog, ComplianceMapping } from "@prisma/client";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FindingKnowledge {
  cweId: string;
  catalog: Pick<VulnerabilityCatalog, "name" | "description" | "extendedDesc" | "severity" | "category" | "remediation" | "references" | "owaspTop10_2021" | "owaspTop10_2017" | "pciDss" | "nist80053" | "gdpr" | "rank" | "year"> | null;
  compliance: ComplianceMapping | null;
  skills: SkillSummary[];
  rootCauses: { title: string; detail: string }[];
  impactExamples: { scenario: string; description: string; cveIds: string[] }[];
  validationGate: { question: string; criteria: string }[];
  chains: { targetSkill: string; primitive: string }[];
  bypassTechniques: string[];
}

export interface SkillSummary {
  id: string;
  slug: string;
  name: string;
  category: string;
  reportCount: number;
  methodology: string | null;
  detectionPatterns: unknown;
  attackSignals: unknown;
}

export interface KnowledgeIndex {
  byCwe: Map<string, HuntSkill[]>;
  byCategory: Map<string, HuntSkill[]>;
  byLanguage: Map<string, HuntSkill[]>;
  allSkills: HuntSkill[];
}

// ─── Query APIs ──────────────────────────────────────────────────────────────

/**
 * Get all active skills mapped to a specific CWE ID.
 */
export async function getSkillsForCwe(cweId: string): Promise<HuntSkill[]> {
  const mappings = await prisma.huntSkillCwe.findMany({
    where: { cweId, skill: { isActive: true } },
    include: { skill: true },
    orderBy: { relevance: "asc" }, // PRIMARY first
  });
  return mappings.map((m) => m.skill);
}

/**
 * Get active skills relevant to given languages/frameworks (for prompt injection).
 */
export async function getSkillsForLanguages(
  languages: string[],
  frameworks?: string[]
): Promise<HuntSkill[]> {
  const skills = await prisma.huntSkill.findMany({
    where: { isActive: true },
  });

  return skills.filter((skill) => {
    const skillLangs = skill.languages as string[];
    const skillFws = skill.frameworks as string[];

    // "all" means universally applicable
    if (skillLangs.includes("all")) return true;

    // Match by language
    const langMatch = skillLangs.some((l) => languages.includes(l));
    if (langMatch) return true;

    // Match by framework
    if (frameworks && frameworks.length > 0) {
      return skillFws.some((f) => frameworks.includes(f));
    }

    return false;
  });
}

/**
 * Get merged knowledge for a specific finding (by CWE ID).
 * Combines: HuntSkill data + VulnerabilityCatalog + ComplianceMapping.
 */
export async function getKnowledgeForFinding(cweId: string): Promise<FindingKnowledge | null> {
  if (!cweId) return null;

  const [catalog, compliance, skillMappings] = await Promise.all([
    prisma.vulnerabilityCatalog.findUnique({
      where: { cweId },
      select: {
        name: true,
        description: true,
        extendedDesc: true,
        severity: true,
        category: true,
        remediation: true,
        references: true,
        owaspTop10_2021: true,
        owaspTop10_2017: true,
        pciDss: true,
        nist80053: true,
        gdpr: true,
        rank: true,
        year: true,
      },
    }),
    prisma.complianceMapping.findUnique({
      where: { cwe: cweId },
    }),
    prisma.huntSkillCwe.findMany({
      where: { cweId, skill: { isActive: true } },
      include: { skill: true },
      orderBy: { relevance: "asc" },
    }),
  ]);

  if (!catalog && !compliance && skillMappings.length === 0) return null;

  const skills = skillMappings.map((m) => m.skill);

  // Merge root causes, impacts, validation gates, chains from all related skills
  const rootCauses: FindingKnowledge["rootCauses"] = [];
  const impactExamples: FindingKnowledge["impactExamples"] = [];
  const validationGate: FindingKnowledge["validationGate"] = [];
  const chains: FindingKnowledge["chains"] = [];
  const bypassTechniques: string[] = [];

  for (const skill of skills) {
    const rc = skill.rootCauses as FindingKnowledge["rootCauses"] | null;
    if (rc) rootCauses.push(...rc);

    const ie = skill.impactExamples as FindingKnowledge["impactExamples"] | null;
    if (ie) impactExamples.push(...ie);

    const vg = skill.validationGate as FindingKnowledge["validationGate"] | null;
    if (vg) validationGate.push(...vg);

    const ch = skill.chains as FindingKnowledge["chains"] | null;
    if (ch) chains.push(...ch);

    const bt = skill.bypassTechniques as string[] | null;
    if (bt) bypassTechniques.push(...bt);
  }

  return {
    cweId,
    catalog,
    compliance,
    skills: skills.map((s) => ({
      id: s.id,
      slug: s.slug,
      name: s.name,
      category: s.category,
      reportCount: s.reportCount,
      methodology: s.methodology,
      detectionPatterns: s.detectionPatterns,
      attackSignals: s.attackSignals,
    })),
    rootCauses: rootCauses.slice(0, 10),
    impactExamples: impactExamples.slice(0, 8),
    validationGate: validationGate.slice(0, 7),
    chains: chains.slice(0, 8),
    bypassTechniques: [...new Set(bypassTechniques)].slice(0, 15),
  };
}

/**
 * Build an in-memory knowledge index for zero-query access during scans.
 * Call once at scan start, pass to all engine functions.
 */
export async function buildKnowledgeIndex(): Promise<KnowledgeIndex> {
  const allSkills = await prisma.huntSkill.findMany({
    where: { isActive: true },
    include: { cweMappings: true },
  });

  const byCwe = new Map<string, HuntSkill[]>();
  const byCategory = new Map<string, HuntSkill[]>();
  const byLanguage = new Map<string, HuntSkill[]>();

  for (const skill of allSkills) {
    // Index by CWE
    const mappings = skill.cweMappings as HuntSkillCwe[];
    for (const mapping of mappings) {
      const existing = byCwe.get(mapping.cweId) || [];
      existing.push(skill);
      byCwe.set(mapping.cweId, existing);
    }

    // Index by category
    const catExisting = byCategory.get(skill.category) || [];
    catExisting.push(skill);
    byCategory.set(skill.category, catExisting);

    // Index by language
    const langs = skill.languages as string[];
    for (const lang of langs) {
      const langExisting = byLanguage.get(lang) || [];
      langExisting.push(skill);
      byLanguage.set(lang, langExisting);
    }
  }

  return { byCwe, byCategory, byLanguage, allSkills };
}

/**
 * Get knowledge context string for AI prompts (token-optimized).
 * Returns a condensed text block with relevant root causes + detection patterns.
 */
export function buildKnowledgeContext(
  index: KnowledgeIndex,
  languages: string[],
  frameworks?: string[],
  maxChars = 3000
): string {
  const relevantSkills = new Set<HuntSkill>();

  // Match by language
  for (const lang of languages) {
    const skills = index.byLanguage.get(lang) || [];
    for (const s of skills) relevantSkills.add(s);
  }
  // "all" skills are universally relevant
  const allSkills = index.byLanguage.get("all") || [];
  for (const s of allSkills) relevantSkills.add(s);

  // Match by framework
  if (frameworks) {
    for (const skill of index.allSkills) {
      const fws = skill.frameworks as string[];
      if (fws.some((f) => frameworks.includes(f))) {
        relevantSkills.add(skill);
      }
    }
  }

  // Build condensed context
  const parts: string[] = [];
  let charCount = 0;

  for (const skill of relevantSkills) {
    if (charCount >= maxChars) break;

    const rootCauses = skill.rootCauses as { title: string; detail: string }[] | null;
    const patterns = skill.detectionPatterns as { name: string; pattern: string }[] | null;

    let entry = `[${skill.name}]`;
    if (rootCauses && rootCauses.length > 0) {
      entry += ` Root causes: ${rootCauses.slice(0, 3).map((r) => r.title).join("; ")}.`;
    }
    if (patterns && patterns.length > 0) {
      entry += ` Detect: ${patterns.slice(0, 2).map((p) => p.name).join("; ")}.`;
    }
    if (skill.methodology) {
      entry += ` Method: ${skill.methodology.slice(0, 200)}.`;
    }

    if (charCount + entry.length <= maxChars) {
      parts.push(entry);
      charCount += entry.length;
    }
  }

  return parts.length > 0
    ? `## BugHunter Knowledge (from ${relevantSkills.size} skills, 681 disclosed reports)\n${parts.join("\n")}`
    : "";
}

/**
 * Get root cause text for a specific CWE from the knowledge index.
 */
export function getRootCauseForCwe(index: KnowledgeIndex, cweId: string): string | null {
  const skills = index.byCwe.get(cweId);
  if (!skills || skills.length === 0) return null;

  const causes: string[] = [];
  for (const skill of skills.slice(0, 2)) {
    const rc = skill.rootCauses as { title: string; detail: string }[] | null;
    if (rc) {
      for (const c of rc.slice(0, 3)) {
        causes.push(c.title);
      }
    }
  }

  return causes.length > 0 ? causes.join("; ") : null;
}

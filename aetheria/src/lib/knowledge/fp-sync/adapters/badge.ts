/**
 * FP Knowledge System — OpenSSF Best Practices Badge adapter (criteria ingest).
 *
 * The OpenSSF Best Practices Badge (https://www.bestpractices.dev) defines a
 * progressive set of criteria across three tiers — passing (0), silver (1) and
 * gold (2) — grouped into Basics / Reporting / Quality / Security / Analysis.
 * Each criterion carries a `category` (MUST | SHOULD | SUGGESTED) plus rich
 * metadata (description, rationale, autofill hints).
 *
 * This adapter clones the `ossf/best-practices-badge` repo and parses
 * `criteria/criteria.yml` into a flat, typed list of criteria. It contributes no
 * FP patterns or CWE knowledge (those don't apply); instead it exposes
 * `parseBadgeCriteria()` as the canonical parser that the Best Practices Badge
 * *assessment* (`scripts/benchmark/assess/badge.ts`) reuses to self-score the
 * EATHERIA repository against the automatable subset of criteria.
 */
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { VENDOR_ROOT, ensureGitRepo } from "../orchestrator";
import type { FpSourceAdapter, NormalizedFpPattern } from "../types";

export const BADGE_REPO = "https://github.com/ossf/best-practices-badge.git";
export const BADGE_DIR = path.join(VENDOR_ROOT, "best-practices-badge");
export const BADGE_CRITERIA_YML = path.join(BADGE_DIR, "criteria", "criteria.yml");

export type BadgeTier = "passing" | "silver" | "gold";
export type BadgeCategory = "MUST" | "SHOULD" | "SUGGESTED";

/** Tier key used in criteria.yml → human tier name. */
const TIER_NAMES: Record<string, BadgeTier> = { "0": "passing", "1": "silver", "2": "gold" };

export interface BadgeCriterion {
  /** Criterion identifier, e.g. `description_good`, `floss_license`. */
  id: string;
  tier: BadgeTier;
  /** Top-level group: Basics | Reporting | Quality | Security | Analysis. */
  majorGroup: string;
  /** Secondary group, e.g. "Basic project website content". */
  minorGroup: string;
  category: BadgeCategory;
  description?: string;
  rationale?: string;
  autofill?: string;
  future?: boolean;
  obsolete?: boolean;
  naAllowed?: boolean;
  metUrlRequired?: boolean;
}

/** Strip HTML tags from a description/rationale blob (criteria.yml embeds HTML). */
function stripHtml(s: string | undefined): string | undefined {
  if (!s) return undefined;
  return s
    .replace(/<[^>]*>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Parse `criteria/criteria.yml` into a flat list of criteria.
 * The file uses YAML `!!omap` tags (ordered maps); we strip them before parsing
 * since JS objects already preserve insertion order. Returns [] if the repo has
 * not been cloned yet (non-fatal).
 */
export function parseBadgeCriteria(): BadgeCriterion[] {
  if (!fs.existsSync(BADGE_CRITERIA_YML)) return [];
  const raw = fs.readFileSync(BADGE_CRITERIA_YML, "utf8").replace(/!!omap/g, "");
  // JSON_SCHEMA only constructs plain maps/lists/scalars (no arbitrary objects).
  const doc = yaml.load(raw, { schema: yaml.JSON_SCHEMA }) as Array<Record<string, unknown>> | null;
  if (!Array.isArray(doc)) return [];

  const criteria: BadgeCriterion[] = [];
  for (const tierNode of doc) {
    const tierKey = Object.keys(tierNode)[0];
    const tier = TIER_NAMES[tierKey];
    if (!tier) continue;
    const majorGroups = tierNode[tierKey] as Array<Record<string, unknown>>;
    if (!Array.isArray(majorGroups)) continue;

    for (const majorNode of majorGroups) {
      const majorGroup = Object.keys(majorNode)[0];
      const minorGroups = majorNode[majorGroup] as Array<Record<string, unknown>>;
      if (!Array.isArray(minorGroups)) continue;

      for (const minorNode of minorGroups) {
        const minorGroup = Object.keys(minorNode)[0];
        const critNodes = minorNode[minorGroup] as Array<Record<string, Record<string, unknown>>>;
        if (!Array.isArray(critNodes)) continue;

        for (const critNode of critNodes) {
          const id = Object.keys(critNode)[0];
          const meta = critNode[id] ?? {};
          const category = String(meta.category ?? "MUST").toUpperCase() as BadgeCategory;
          criteria.push({
            id,
            tier,
            majorGroup,
            minorGroup,
            category,
            description: stripHtml(meta.description as string | undefined),
            rationale: stripHtml(meta.rationale as string | undefined),
            autofill: typeof meta.autofill === "string" ? meta.autofill.trim() : undefined,
            future: meta.future === true,
            obsolete: meta.obsolete === true,
            naAllowed: meta.na_allowed === true,
            metUrlRequired: meta.met_url_required === true,
          });
        }
      }
    }
  }
  return criteria;
}

export class BadgeAdapter implements FpSourceAdapter {
  id = "badge";
  name = "OpenSSF Best Practices Badge (criteria)";

  async fetch(): Promise<void> {
    ensureGitRepo(BADGE_REPO, BADGE_DIR);
  }

  /** Badge criteria are not FP patterns. */
  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    return [];
  }
}

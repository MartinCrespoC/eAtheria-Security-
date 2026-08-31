/**
 * OpenSSF Best Practices Badge — setup.
 *
 * Clones the `ossf/best-practices-badge` repository (the canonical home of the
 * criteria definitions) into `vendor/fp/best-practices-badge` and reports how
 * many criteria were parsed per tier. The assessment step
 * (`scripts/benchmark/assess/badge.ts`) reuses the same parser.
 */
import { ensureGitRepo } from "../../../src/lib/knowledge/fp-sync/orchestrator";
import {
  BADGE_REPO,
  BADGE_DIR,
  BADGE_CRITERIA_YML,
  parseBadgeCriteria,
  type BadgeTier,
} from "../../../src/lib/knowledge/fp-sync/adapters/badge";

/** Clone/pull the badge repo and report the parsed criteria counts per tier. */
export function setupBadge(): { total: number; perTier: Record<BadgeTier, number>; dir: string } {
  console.log("\n📦 [badge] OpenSSF Best Practices Badge setup");
  ensureGitRepo(BADGE_REPO, BADGE_DIR);

  const criteria = parseBadgeCriteria();
  const perTier: Record<BadgeTier, number> = { passing: 0, silver: 0, gold: 0 };
  for (const c of criteria) perTier[c.tier]++;

  console.log(`   ✓ ${criteria.length} criteria parsed from ${BADGE_CRITERIA_YML}`);
  console.log(`     passing: ${perTier.passing} · silver: ${perTier.silver} · gold: ${perTier.gold}`);
  return { total: criteria.length, perTier, dir: BADGE_DIR };
}

/**
 * OWASP WSTG — setup.
 *
 * Clones the OWASP Web Security Testing Guide markdown into `vendor/fp/wstg`
 * and reports how many test documents were parsed and how many CWEs they cover.
 * The knowledge sync (`sync:fp`) and the WSTG detection benchmark both consume
 * the same parsed index.
 */
import { ensureGitRepo } from "../../../src/lib/knowledge/fp-sync/orchestrator";
import { WSTG_REPO, WSTG_DIR, parseWstgDocuments, cwesForDocument } from "../../../src/lib/knowledge/fp-sync/adapters/wstg";

/** Clone/pull the WSTG repo and report the parsed test-document index. */
export function setupWstg(): { tests: number; cwes: number; dir: string } {
  console.log("\n📦 [wstg] OWASP WSTG setup");
  ensureGitRepo(WSTG_REPO, WSTG_DIR);

  const docs = parseWstgDocuments();
  const cwes = new Set<string>();
  for (const d of docs) for (const c of cwesForDocument(d)) cwes.add(c);

  console.log(`   ✓ ${docs.length} WSTG test documents parsed from ${WSTG_DIR}`);
  console.log(`   ✓ mapping to ${cwes.size} distinct CWEs`);
  return { tests: docs.length, cwes: cwes.size, dir: WSTG_DIR };
}

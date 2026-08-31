/**
 * BugHunter Knowledge Sync Script
 * Clones (or pulls) the Claude-BugHunter repo and syncs all skills to the database.
 * Run with: npm run sync:knowledge
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { prisma } from "../src/lib/db";

const REPO_URL = "https://github.com/elementalsouls/Claude-BugHunter.git";
const VENDOR_DIR = path.join(process.cwd(), "vendor", "bughunter");

async function main() {
  console.log("🔍 BugHunter Knowledge Sync");
  console.log("═══════════════════════════════════════════\n");

  // Step 1: Clone or pull the repo
  await ensureRepo();

  // Step 2: Run sync
  const { syncHuntSkills } = await import("../src/lib/knowledge/sync");
  const stats = await syncHuntSkills({ vendorDir: VENDOR_DIR, force: true });

  // Step 3: Print summary
  console.log("\n═══════════════════════════════════════════");
  console.log("📊 Sync Summary:");
  console.log(`   Total skill dirs found: ${stats.total}`);
  console.log(`   Upserted: ${stats.created}`);
  console.log(`   Skipped: ${stats.skipped}`);
  console.log(`   Errors: ${stats.errors.length}`);

  if (stats.errors.length > 0) {
    console.log("\n⚠️  Errors:");
    for (const err of stats.errors) {
      console.log(`   - ${err}`);
    }
  }

  // Verify DB count
  const dbCount = await prisma.huntSkill.count();
  const cweCount = await prisma.huntSkillCwe.count();
  console.log(`\n✅ Database state: ${dbCount} skills, ${cweCount} CWE mappings`);
}

function ensureRepo(): void {
  if (fs.existsSync(path.join(VENDOR_DIR, ".git"))) {
    console.log("📂 Repo exists, pulling latest...");
    try {
      execFileSync("git", ["pull", "--ff-only"], { cwd: VENDOR_DIR, stdio: "pipe" });
      console.log("   ✓ Updated to latest\n");
    } catch {
      console.log("   ⚠ Pull failed, using existing clone\n");
    }
  } else {
    console.log("📥 Cloning Claude-BugHunter repo...");
    const vendorParent = path.dirname(VENDOR_DIR);
    if (!fs.existsSync(vendorParent)) {
      fs.mkdirSync(vendorParent, { recursive: true });
    }
    try {
      execFileSync("git", ["clone", "--depth", "1", REPO_URL, VENDOR_DIR], {
        stdio: "pipe",
        timeout: 60000,
      });
      console.log("   ✓ Clone complete\n");
    } catch (err) {
      console.error("   ✗ Clone failed:", err instanceof Error ? err.message : err);
      console.error("   Please clone manually:");
      console.error(`   git clone --depth 1 ${REPO_URL} vendor/bughunter\n`);
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

/**
 * Seed False Positive Patterns Database
 * Run with: npx tsx scripts/seed-false-positives.ts
 */

import { PrismaClient } from "@prisma/client";
import { ALL_FALSE_POSITIVE_PATTERNS } from "../src/lib/false-positives";

const prisma = new PrismaClient();

async function seedFalsePositives() {
  console.log("🚀 Starting False Positive Patterns seeding...\n");

  // Clean existing CURATED patterns for idempotent reseed.
  // Scoped to builtin/manual so ingested patterns (gitleaks/cwe/semgrep/juliet)
  // from `npm run sync:fp` are preserved.
  const deleted = await prisma.falsePositivePattern.deleteMany({
    where: { source: { in: ["builtin", "manual"] } },
  });
  if (deleted.count > 0) {
    console.log(`   🗑️  Cleared ${deleted.count} existing curated patterns\n`);
  }

  let created = 0;
  let skipped = 0;

  for (const pattern of ALL_FALSE_POSITIVE_PATTERNS) {
    try {
      await prisma.falsePositivePattern.create({
        data: {
          language: pattern.language,
          pattern: pattern.pattern,
          description: pattern.description,
          reason: pattern.reason,
          context: pattern.context,
          cweIds: pattern.cweIds,
          examples: pattern.examples,
          isActive: true,
          source: "builtin",
          confidence: 90,
          category: "curated",
        },
      });
      console.log(`   ✅ Created: ${pattern.language} - ${pattern.description}`);
      created++;
    } catch (error) {
      console.log(`   ⏭️  Skipped: ${pattern.language} - ${pattern.description}`);
      skipped++;
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log(`✨ False Positive Patterns seeding complete!`);
  console.log(`   Created: ${created}`);
  console.log(`   Skipped: ${skipped}`);
  console.log(`   Total: ${ALL_FALSE_POSITIVE_PATTERNS.length}`);
  console.log("=".repeat(60));
}

// Run if called directly
if (require.main === module) {
  seedFalsePositives()
    .then(() => {
      console.log("\n✅ Script completed successfully");
      process.exit(0);
    })
    .catch((error) => {
      console.error("\n❌ Script failed:", error);
      process.exit(1);
    })
    .finally(() => {
      prisma.$disconnect();
    });
}

export { seedFalsePositives };

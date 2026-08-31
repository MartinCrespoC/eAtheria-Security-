/**
 * Seed CWE Top 25 2025 Database
 * Run with: npx tsx scripts/seed-cwe-2025.ts
 */

import { PrismaClient } from "@prisma/client";
import { CWE_TOP_25_2025, CWE_DESCRIPTIONS } from "../src/lib/cwe/cwe-2025-data";

const prisma = new PrismaClient();

async function seedCWE2025() {
  console.log("🚀 Starting CWE Top 25 2025 seeding...\n");

  let created = 0;
  let updated = 0;
  let skipped = 0;

  for (const cwe of CWE_TOP_25_2025) {
    try {
      const details = CWE_DESCRIPTIONS[cwe.cweId] || {
        description: `${cwe.name} - Details to be added`,
        remediation: "See MITRE CWE for remediation guidance",
        languages: ["Multiple"],
      };

      const existing = await prisma.vulnerabilityCatalog.findUnique({
        where: { cweId: cwe.cweId },
      });

      if (existing) {
        // Update existing
        await prisma.vulnerabilityCatalog.update({
          where: { cweId: cwe.cweId },
          data: {
            year: 2025,
            rank: cwe.rank,
            kevCount: cwe.kevCount,
            source: "MITRE_2025",
            lastSyncedAt: new Date(),
            category: cwe.category,
            severity: cwe.severity,
          },
        });
        console.log(`   ✅ Updated: ${cwe.cweId} - ${cwe.name}`);
        updated++;
      } else {
        // Create new
        await prisma.vulnerabilityCatalog.create({
          data: {
            cweId: cwe.cweId,
            name: cwe.name,
            description: details.description,
            severity: cwe.severity,
            category: cwe.category,
            year: 2025,
            rank: cwe.rank,
            kevCount: cwe.kevCount,
            source: "MITRE_2025",
            lastSyncedAt: new Date(),
            languages: details.languages,
            remediation: details.remediation,
            references: [
              `https://cwe.mitre.org/data/definitions/${cwe.cweId.replace("CWE-", "")}.html`,
              "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
            ],
            isActive: true,
          },
        });
        console.log(`   ✅ Created: ${cwe.cweId} - ${cwe.name}`);
        created++;
      }
    } catch (error) {
      console.error(`   ❌ Error processing ${cwe.cweId}:`, error);
      skipped++;
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log(`✨ CWE Top 25 2025 seeding complete!`);
  console.log(`   Created: ${created}`);
  console.log(`   Updated: ${updated}`);
  console.log(`   Skipped: ${skipped}`);
  console.log(`   Total: ${CWE_TOP_25_2025.length}`);
  console.log("=".repeat(60));
}

// Run if called directly
if (require.main === module) {
  seedCWE2025()
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

export { seedCWE2025 };

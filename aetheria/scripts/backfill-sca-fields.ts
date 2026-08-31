/**
 * Backfill SCA Fields Script
 * Updates existing category: "Dependency" vulnerabilities with:
 * - detectionMethod: "SCA"
 * - packageName / packageVersion / ecosystem (parsed from title/description)
 *
 * Usage: npx tsx scripts/backfill-sca-fields.ts
 */

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const ECOSYSTEM_PATTERNS: { pattern: RegExp; ecosystem: string }[] = [
  { pattern: /npm|node_modules|package\.json/i, ecosystem: "npm" },
  { pattern: /pypi|pip|requirements\.txt|setup\.py/i, ecosystem: "PyPI" },
  { pattern: /maven|pom\.xml|gradle|\.jar/i, ecosystem: "Maven" },
  { pattern: /go\.mod|go\.sum|golang/i, ecosystem: "Go" },
  { pattern: /cargo|crates\.io|\.rs/i, ecosystem: "crates" },
  { pattern: /gemfile|rubygems|\.gem/i, ecosystem: "rubygems" },
];

// Patterns to extract package name and version from text
const PKG_PATTERNS: RegExp[] = [
  /([@\w][\w./-]+)@(\d+[\d.]*[\w.-]*)/,          // package@1.2.3
  /([@\w][\w./-]+)\s+v?(\d+[\d.]*[\w.-]*)/,       // package v1.2.3
  /"([@\w][\w./-]+)":\s*"[\^~]?(\d+[\d.]*[\w.-]*)"/, // "package": "^1.2.3"
  /([@\w][\w./-]+)\s*\(v?(\d+[\d.]*[\w.-]*)\)/,   // package (1.2.3)
];

function detectEcosystem(text: string): string | null {
  for (const { pattern, ecosystem } of ECOSYSTEM_PATTERNS) {
    if (pattern.test(text)) return ecosystem;
  }
  return null;
}

function extractPackageInfo(text: string): { name: string | null; version: string | null } {
  for (const pattern of PKG_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      return { name: match[1], version: match[2] };
    }
  }
  return { name: null, version: null };
}

async function main() {
  console.log("[BACKFILL] Starting SCA field backfill...\n");

  // Find all Dependency vulns missing detectionMethod
  const vulns = await prisma.vulnerability.findMany({
    where: {
      category: "Dependency",
      OR: [
        { detectionMethod: null },
        { detectionMethod: "" },
      ],
    },
    select: {
      id: true,
      title: true,
      description: true,
    },
  });

  console.log(`[BACKFILL] Found ${vulns.length} Dependency vulnerabilities to backfill\n`);

  let updated = 0;
  let skipped = 0;

  for (const vuln of vulns) {
    const combinedText = `${vuln.title} ${vuln.description}`;
    const ecosystem = detectEcosystem(combinedText);
    const { name, version } = extractPackageInfo(combinedText);

    const data: Record<string, unknown> = {
      detectionMethod: "SCA",
    };

    if (name) data.packageName = name;
    if (version) data.packageVersion = version;
    if (ecosystem) data.ecosystem = ecosystem;
    if (!data.packageName) {
      // Try to extract package name from title as fallback
      const titleMatch = vuln.title.match(/(?:in|for|package)\s+([@\w][\w./-]+)/i);
      if (titleMatch) data.packageName = titleMatch[1];
    }

    try {
      await prisma.vulnerability.update({
        where: { id: vuln.id },
        data,
      });
      updated++;
      if (updated % 10 === 0) {
        console.log(`[BACKFILL] Progress: ${updated}/${vulns.length}`);
      }
    } catch (err) {
      skipped++;
      console.error(`[BACKFILL] Error updating ${vuln.id}: ${err instanceof Error ? err.message : "Unknown"}`);
    }
  }

  console.log(`\n[BACKFILL] Complete: ${updated} updated, ${skipped} errors`);

  // Verify
  const remaining = await prisma.vulnerability.count({
    where: {
      category: "Dependency",
      OR: [
        { detectionMethod: null },
        { detectionMethod: "" },
      ],
    },
  });
  console.log(`[BACKFILL] Remaining without detectionMethod: ${remaining}`);
}

main()
  .catch((e) => {
    console.error("[BACKFILL] Fatal error:", e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

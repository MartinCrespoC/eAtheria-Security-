/**
 * Trigger a new scan on SurveysFarma to test the expanded DB rules.
 * Run: npx tsx scripts/run-scan-test.ts
 */
import { prisma } from "../src/lib/db";
import { triggerAnalysis } from "../src/lib/analysis/trigger";

async function main() {
  console.log("[SCAN-TEST] Creating new analysis for SurveysFarma v2.0...");

  const analysis = await prisma.analysis.create({
    data: {
      appVersionId: "cms2kn8f4000ncp0bxyrhlfjk",
      scanTypes: ["SAST", "SCA"],
      scanLevel: "STATIC",
      aiValidation: false,
      triggeredBy: "scan-test-v2",
      status: "PENDING",
    },
  });

  console.log(`[SCAN-TEST] Analysis created: ${analysis.id}`);
  console.log("[SCAN-TEST] Triggering deterministic scan (L1 engines, no AI)...");

  await triggerAnalysis(analysis.id);

  console.log("[SCAN-TEST] Scan complete! Fetching results...\n");

  const result = await prisma.analysis.findUnique({
    where: { id: analysis.id },
    include: {
      vulnerabilities: {
        select: {
          id: true,
          title: true,
          severity: true,
          cweId: true,
          category: true,
          detectionMethod: true,
          deltaStatus: true,
          filePath: true,
          confidence: true,
        },
        orderBy: [{ severity: "desc" }, { cweId: "asc" }],
      },
    },
  });

  if (!result) {
    console.error("Analysis not found after trigger!");
    process.exit(1);
  }

  console.log("═══════════════════════════════════════════════════════");
  console.log("           SCAN RESULTS — SurveysFarma v2.0");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`Status: ${result.status}`);
  console.log(`Total Findings: ${result.vulnerabilities.length}`);
  console.log(`Previous scan: 43 findings`);
  console.log("");

  // By Severity
  const bySev: Record<string, number> = {};
  result.vulnerabilities.forEach((v) => {
    bySev[v.severity] = (bySev[v.severity] || 0) + 1;
  });
  console.log("📊 By Severity:");
  for (const [sev, count] of Object.entries(bySev).sort()) {
    console.log(`   ${sev}: ${count}`);
  }

  // By Detection Method
  const byMethod: Record<string, number> = {};
  result.vulnerabilities.forEach((v) => {
    byMethod[v.detectionMethod || "AI_SAST"] = (byMethod[v.detectionMethod || "AI_SAST"] || 0) + 1;
  });
  console.log("\n🔍 By Detection Method:");
  for (const [method, count] of Object.entries(byMethod).sort()) {
    console.log(`   ${method}: ${count}`);
  }

  // By CWE
  const byCwe: Record<string, number> = {};
  result.vulnerabilities.forEach((v) => {
    byCwe[v.cweId] = (byCwe[v.cweId] || 0) + 1;
  });
  console.log("\n🏷️  By CWE:");
  for (const [cwe, count] of Object.entries(byCwe).sort()) {
    console.log(`   ${cwe}: ${count}`);
  }

  // Delta Status
  const byDelta: Record<string, number> = {};
  result.vulnerabilities.forEach((v) => {
    byDelta[v.deltaStatus || "N/A"] = (byDelta[v.deltaStatus || "N/A"] || 0) + 1;
  });
  console.log("\n🔄 Delta Status (vs previous scan):");
  for (const [status, count] of Object.entries(byDelta).sort()) {
    console.log(`   ${status}: ${count}`);
  }

  // Full list
  console.log("\n───────────────────────────────────────────────────────");
  console.log("📋 Full Findings List:");
  console.log("───────────────────────────────────────────────────────");
  result.vulnerabilities.forEach((v, i) => {
    console.log(
      `  ${String(i + 1).padStart(3)}. [${v.severity.padEnd(8)}] ${v.title}`
    );
    console.log(
      `       CWE: ${v.cweId} | Method: ${v.detectionMethod || "AI"} | Delta: ${v.deltaStatus || "-"} | File: ${v.filePath}`
    );
  });

  console.log("\n═══════════════════════════════════════════════════════");
  console.log(`✅ Done. Analysis ID: ${analysis.id}`);
}

main()
  .catch((e) => {
    console.error("FATAL:", e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

import { prisma } from "../src/lib/db";
async function main() {
  const catCount = await prisma.vulnerabilityCatalog.count();
  const catActive = await prisma.vulnerabilityCatalog.count({ where: { isActive: true } });
  const withRemediation = await prisma.vulnerabilityCatalog.count({ where: { remediation: { not: null } } });
  const withRefs = await prisma.vulnerabilityCatalog.count({ where: { references: { not: null } } });
  const compCount = await prisma.complianceMapping.count();
  console.log("VulnerabilityCatalog: total", catCount, "| active", catActive, "| withRemediation", withRemediation, "| withReferences", withRefs);
  console.log("ComplianceMapping:", compCount);
  const sample = await prisma.vulnerabilityCatalog.findFirst({ where: { cweId: "CWE-89" } });
  console.log("\nSample CWE-89 catalog entry:");
  console.log(JSON.stringify(sample, null, 2));
  const cats = await prisma.vulnerabilityCatalog.groupBy({ by: ["category"], _count: true, orderBy: { _count: { category: "desc" } } });
  console.log("\nCategories:", JSON.stringify(Object.fromEntries(cats.map(c => [c.category, c._count]))));
}
main().catch(e => { console.error("ERR:", e.message); process.exit(1); }).finally(() => prisma.$disconnect());

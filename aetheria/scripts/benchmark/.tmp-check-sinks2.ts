import { prisma } from "../../src/lib/db";

async function main() {
  const sinks = await prisma.taintSink.findMany({
    where: { cwe: "CWE-78" }
  });
  console.log("CWE-78 sinks:");
  for (const s of sinks) {
    console.log(`  [${s.language}] ${s.pattern} (${s.category})`);
  }
  await prisma.$disconnect();
}

main().catch(console.error);

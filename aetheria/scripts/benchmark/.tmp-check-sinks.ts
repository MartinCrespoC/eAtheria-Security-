import { prisma } from "../../src/lib/db";

async function main() {
  const sinks = await prisma.taintSink.findMany({
    where: { language: { in: ["java", "*"] }, category: "cmdi" }
  });
  console.log("cmdi sinks:");
  for (const s of sinks) {
    console.log(`  ${s.pattern} (${s.cwe})`);
  }
  await prisma.$disconnect();
}

main().catch(console.error);

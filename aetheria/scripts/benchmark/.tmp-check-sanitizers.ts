import { prisma } from "../../src/lib/db";

async function main() {
  const sanitizers = await prisma.taintSanitizer.findMany({
    where: { language: { in: ["java", "*"] } }
  });
  console.log("Java sanitizers:");
  for (const s of sanitizers) {
    console.log(`  ${s.pattern}`);
  }
  await prisma.$disconnect();
}

main().catch(console.error);

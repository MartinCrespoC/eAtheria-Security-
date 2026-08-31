import * as fs from "fs";
import { prisma } from "../../src/lib/db";
import { detectInCode, hasKeptFindingForCwe } from "./detect";

async function main() {
  const testCases = ["BenchmarkTest00098", "BenchmarkTest00321", "BenchmarkTest00324"];
  
  for (const name of testCases) {
    const code = fs.readFileSync(`vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/${name}.java`, "utf-8");
    const findings = await detectInCode({
      fileContent: code,
      filePath: `${name}.java`,
      language: "java",
    });
    const detected = hasKeptFindingForCwe(findings, "CWE-501");
    console.log(`${name}: ${detected ? "DETECTED" : "MISSED"}`);
    if (!detected) {
      const kept = findings.filter(f => f.kept);
      console.log(`  Kept findings: ${kept.map(f => f.cweId).join(", ") || "none"}`);
    }
  }
  
  await prisma.$disconnect();
}

main().catch(console.error);

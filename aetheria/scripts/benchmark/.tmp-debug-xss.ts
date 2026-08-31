import * as fs from "fs";
import { prisma } from "../../src/lib/db";
import { detectInCode, hasKeptFindingForCwe } from "./detect";

async function main() {
  const testCases = ["BenchmarkTest01046", "BenchmarkTest01050", "BenchmarkTest01063"];
  
  for (const name of testCases) {
    const code = fs.readFileSync(`vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/${name}.java`, "utf-8");
    const findings = await detectInCode({ fileContent: code, filePath: `${name}.java`, language: "java" });
    const detected = hasKeptFindingForCwe(findings, "CWE-79") || hasKeptFindingForCwe(findings, "CWE-80");
    console.log(`${name}: ${detected ? "DETECTED" : "MISSED"}`);
  }
  
  await prisma.$disconnect();
}

main().catch(console.error);

import * as fs from "fs";
import { prisma } from "../../src/lib/db";
import { detectInCode, hasKeptFindingForCwe } from "./detect";

async function main() {
  // Test TRUE case
  const code1 = fs.readFileSync("vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00006.java", "utf-8");
  const findings1 = await detectInCode({ fileContent: code1, filePath: "BenchmarkTest00006.java", language: "java" });
  console.log(`BenchmarkTest00006 (TRUE): ${hasKeptFindingForCwe(findings1, "CWE-78") ? "DETECTED" : "MISSED"}`);
  
  // Test FALSE case (list-add-remove-get pattern)
  const code2 = fs.readFileSync("vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00093.java", "utf-8");
  const findings2 = await detectInCode({ fileContent: code2, filePath: "BenchmarkTest00093.java", language: "java" });
  console.log(`BenchmarkTest00093 (FALSE): ${hasKeptFindingForCwe(findings2, "CWE-78") ? "FP!" : "OK (no detection)"}`);
  
  await prisma.$disconnect();
}

main().catch(console.error);

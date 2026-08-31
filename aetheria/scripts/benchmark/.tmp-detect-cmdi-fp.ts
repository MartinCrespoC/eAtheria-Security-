import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../src/lib/db";
import { detectInCode, hasKeptFindingForCwe } from "./detect";

const CSV = "vendor/fp/owasp-benchmark/expectedresults-1.2.csv";
const TESTCODE = "vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode";

async function main() {
  const csv = fs.readFileSync(CSV, "utf-8");
  const falseCases = csv.split("\n")
    .filter(l => l.includes(",cmdi,false,"))
    .map(l => l.split(",")[0]);

  console.log(`Testing ALL ${falseCases.length} cmdi FALSE cases...`);

  const detected: string[] = [];
  
  for (const name of falseCases) {
    const file = path.join(TESTCODE, `${name}.java`);
    if (!fs.existsSync(file)) continue;
    const code = fs.readFileSync(file, "utf-8");
    
    const findings = await detectInCode({
      fileContent: code,
      filePath: `${name}.java`,
      language: "java",
    });
    
    // Check using the same method as the benchmark
    const detectedCwe78 = hasKeptFindingForCwe(findings, "CWE-78");
    
    if (detectedCwe78) {
      detected.push(name);
      const kept = findings.filter(f => f.kept);
      console.log(`FP: ${name} - kept findings: ${kept.map(f => f.cweId).join(", ")}`);
    }
  }
  
  console.log(`\nDetected ${detected.length} FPs out of ${falseCases.length} FALSE cases`);
  console.log(`FPR = ${detected.length}/${falseCases.length} = ${(100*detected.length/falseCases.length).toFixed(1)}%`);
  await prisma.$disconnect();
}

main().catch(console.error);

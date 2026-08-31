import * as fs from "fs";
import * as path from "path";
import { prisma } from "../../src/lib/db";
import { detectInCode, hasKeptFindingForCwe } from "./detect";

const CSV = "vendor/fp/owasp-benchmark/expectedresults-1.2.csv";
const TESTCODE = "vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode";

async function main() {
  const csv = fs.readFileSync(CSV, "utf-8");
  const trueCases = csv.split("\n")
    .filter(l => l.includes(",trustbound,true,"))
    .map(l => l.split(",")[0]);

  console.log(`Testing ${trueCases.length} trustbound TRUE cases for FNs...`);

  const fns: string[] = [];
  
  for (const name of trueCases) {
    const file = path.join(TESTCODE, `${name}.java`);
    if (!fs.existsSync(file)) continue;
    const code = fs.readFileSync(file, "utf-8");
    
    const findings = await detectInCode({
      fileContent: code,
      filePath: `${name}.java`,
      language: "java",
    });
    
    const detected = hasKeptFindingForCwe(findings, "CWE-501");
    
    if (!detected) {
      fns.push(name);
    }
  }
  
  console.log(`\nFNs: ${fns.length} out of ${trueCases.length}`);
  console.log(`TPR = ${trueCases.length - fns.length}/${trueCases.length} = ${(100*(trueCases.length - fns.length)/trueCases.length).toFixed(1)}%`);
  console.log(`\nFN cases: ${fns.slice(0, 15).join(", ")}`);
  await prisma.$disconnect();
}

main().catch(console.error);

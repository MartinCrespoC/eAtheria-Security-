import * as fs from "fs";
import { prisma } from "../../src/lib/db";
import { runTaintAnalysis, type TaintRulesBundle } from "../../src/lib/analysis/engines/taint-engine";

async function main() {
  const code = fs.readFileSync("vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00077.java", "utf-8");
  
  const sources = await prisma.taintSource.findMany();
  const sinks = await prisma.taintSink.findMany();
  const sanitizers = await prisma.taintSanitizer.findMany();
  const rules: TaintRulesBundle = { sources, sinks, sanitizers };
  
  const findings = runTaintAnalysis(code, "BenchmarkTest00077.java", "java", rules);
  console.log("Findings:", findings.length);
  for (const f of findings) {
    console.log(`  ${f.cwe} @ line ${f.lineStart}-${f.lineEnd}: ${f.title}`);
  }
  
  await prisma.$disconnect();
}

main().catch(console.error);

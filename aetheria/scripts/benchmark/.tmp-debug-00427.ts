import * as fs from "fs";
import { prisma } from "../../src/lib/db";
import { runTaintAnalysis, computeTaintedVarNames, type TaintRulesBundle } from "../../src/lib/analysis/engines/taint-engine";

async function main() {
  const code = fs.readFileSync("vendor/fp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00427.java", "utf-8");
  
  const sources = await prisma.taintSource.findMany();
  const sinks = await prisma.taintSink.findMany();
  const sanitizers = await prisma.taintSanitizer.findMany();
  const rules: TaintRulesBundle = { sources, sinks, sanitizers };
  
  // Get tainted vars (with sanitizers skipped for trustbound)
  const tainted = computeTaintedVarNames(code, "java", rules, true);
  console.log("Tainted vars (skip sanitizers):", [...tainted].join(", "));
  
  // Get tainted vars (with sanitizers)
  const tainted2 = computeTaintedVarNames(code, "java", rules, false);
  console.log("Tainted vars (with sanitizers):", [...tainted2].join(", "));
  
  await prisma.$disconnect();
}

main().catch(console.error);

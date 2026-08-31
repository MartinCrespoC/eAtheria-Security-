/**
 * Juliet benchmark parser — delegates to the JulietAdapter (Fase 2d), which
 * walks `vendor/fp/juliet` for `CWE###_..._NN.java` files and extracts labeled
 * cases (bad() → expected TP, goodN() → expected FP). Returns [] if the dataset
 * is not present (it is a licensed NIST download placed manually).
 */
import { JulietAdapter } from "../../../src/lib/knowledge/fp-sync/adapters/juliet";
import type { BenchmarkCaseInput } from "../../../src/lib/knowledge/fp-sync/types";

export async function parseJulietCases(): Promise<BenchmarkCaseInput[]> {
  const adapter = new JulietAdapter();
  await adapter.fetch(); // ensures dir exists; no download
  return adapter.parseBenchmarkCases!();
}

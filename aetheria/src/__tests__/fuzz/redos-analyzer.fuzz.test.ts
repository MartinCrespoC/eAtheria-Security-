/**
 * Property-based fuzzing of the structural ReDoS analyzer.
 *
 * `analyzeReDoSPattern` is a hand-rolled regex-pattern parser on the security
 * hot path — a crash or unbounded runtime here would break or stall scans.
 * These fast-check properties assert, over generated inputs:
 *   1. robustness — the analyzer never throws, on arbitrary or regex-shaped input
 *   2. bounded runtime — analysis completes well within a per-call budget
 *   3. determinism — identical patterns always yield identical verdicts
 *
 * Run with the unit suite (`npm test`) or alone:
 *   npx vitest run src/__tests__/fuzz/redos-analyzer.fuzz.test.ts
 */
import { describe, it } from "vitest";
import * as fc from "fast-check";
import { analyzeReDoSPattern } from "../../lib/analysis/engines/weakness-engine";

const REGEX_TOKENS = [
  "a",
  "b",
  ".",
  "*",
  "+",
  "?",
  "\\w",
  "\\d",
  "\\s",
  "[a-z]",
  "[^\\n]",
  "(a|b)",
  "(?:ab)",
  "(?=a)",
  "{1,3}",
  "{2,}",
  "^",
  "$",
  "|",
];

const regexShaped = fc
  .array(fc.constantFrom(...REGEX_TOKENS), { minLength: 1, maxLength: 14 })
  .map((parts) => parts.join(""));

describe("fuzz: analyzeReDoSPattern", () => {
  it("never throws on arbitrary strings", () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        analyzeReDoSPattern(input);
      }),
      { numRuns: 500 }
    );
  });

  it("never throws on regex-shaped inputs and stays within the time budget", () => {
    fc.assert(
      fc.property(regexShaped, (pattern) => {
        const start = performance.now();
        analyzeReDoSPattern(pattern);
        const elapsed = performance.now() - start;
        // Generous ceiling: CI machines vary; the property being guarded is
        // "no unbounded blowup", not micro-performance.
        if (elapsed > 500) {
          throw new Error(`analysis took ${elapsed.toFixed(1)}ms for ${JSON.stringify(pattern)}`);
        }
      }),
      { numRuns: 1000 }
    );
  });

  it("is deterministic: same pattern, same verdict", () => {
    fc.assert(
      fc.property(regexShaped, (pattern) => {
        const first = analyzeReDoSPattern(pattern);
        const second = analyzeReDoSPattern(pattern);
        if (first !== second) {
          throw new Error(
            `non-deterministic verdict for ${JSON.stringify(pattern)}: ${JSON.stringify(first)} vs ${JSON.stringify(second)}`
          );
        }
      }),
      { numRuns: 300 }
    );
  });

  it("known pathological shapes are flagged; known linear shapes are not", () => {
    // Anchor examples keep the fuzzer honest: if generation ever stops
    // covering these, the properties above lose meaning.
    if (analyzeReDoSPattern("^(a+)+$") === null) {
      throw new Error("expected (a+)+ to be flagged as ReDoS-prone");
    }
    if (analyzeReDoSPattern("^[a-z]+$") !== null) {
      throw new Error("expected [a-z]+ to be reported safe");
    }
  });
});

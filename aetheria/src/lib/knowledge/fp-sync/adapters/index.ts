/**
 * FP Knowledge System — adapter registry.
 *
 * Central list of all ingestion sources. The sync CLI (`scripts/sync-fp-knowledge.ts`)
 * and the benchmark runner consume this registry. Order reflects rollout
 * risk/value: gitleaks (immediate secret FPs) → CWE (knowledge) → Semgrep
 * (CWE→FP knowledge) → Juliet (benchmark cases).
 */
import type { FpSourceAdapter } from "../types";
import { GitleaksAdapter } from "./gitleaks";
import { CweAdapter } from "./cwe";
import { SemgrepAdapter } from "./semgrep";
import { JulietAdapter } from "./juliet";
import { BadgeAdapter } from "./badge";
import { WstgAdapter } from "./wstg";

export const ALL_FP_ADAPTERS: FpSourceAdapter[] = [
  new GitleaksAdapter(),
  new CweAdapter(),
  new SemgrepAdapter(),
  new JulietAdapter(),
  new BadgeAdapter(),
  new WstgAdapter(),
];

export { GitleaksAdapter, CweAdapter, SemgrepAdapter, JulietAdapter, BadgeAdapter, WstgAdapter };

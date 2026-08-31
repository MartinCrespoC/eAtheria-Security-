/**
 * FP Knowledge System — shared types.
 *
 * The system ingests false-positive knowledge from multiple external sources
 * (gitleaks, MITRE CWE, Semgrep, NIST Juliet) and normalizes it into a common
 * shape that can be upserted into the `FalsePositivePattern` table and/or used
 * to enrich CWE knowledge and the AI prompt.
 */

/**
 * A source-agnostic false-positive pattern ready to be persisted.
 * Compatible with the curated `ALL_FALSE_POSITIVE_PATTERNS` shape, plus
 * provenance/ranking fields used for idempotent upsert and thresholding.
 */
export interface NormalizedFpPattern {
  /** Language key ("javascript", "python", ...) or "*" for language-agnostic. */
  language: string;
  /** A valid JS regular expression (validated before insert). */
  pattern: string;
  description: string;
  /** Why matching code is a false positive. */
  reason: string;
  context?: string | null;
  cweIds: string[];
  examples?: string[];
  /** Provenance: "gitleaks" | "cwe" | "semgrep" | "juliet" | "builtin" | "manual". */
  source: string;
  /** Stable external rule id — used for idempotent upsert/dedup. */
  sourceRuleId: string;
  /** 0-100; gated against the scan-level fpConfidenceThreshold. */
  confidence: number;
  /** "secret" | "xss" | "sqli" | "path-traversal" | "open-redirect" | ... */
  category?: string;
}

/**
 * Enriched CWE knowledge extracted from MITRE CWE (and Semgrep precision data).
 * Persisted into the `CweKnowledge` table and fed to the AI prompt.
 */
export interface NormalizedCweKnowledge {
  cweId: string;
  name: string;
  category?: string;
  description?: string;
  extendedDescription?: string;
  commonFalsePositives: string[];
  /** "DO NOT FLAG" guidance lines injected into the SAST AI prompt. */
  doNotFlag: string[];
  detectionMethods: string[];
  mitigations: string[];
  owaspTop10?: string;
  mitreTop25Rank?: number;
  source: string;
}

/** A single labeled benchmark case (OWASP Benchmark / Juliet). */
export interface BenchmarkCaseInput {
  cweId: string;
  category: string;
  /** "TP" = real vulnerability, "FP" = safe code that naive tools flag. */
  expected: "TP" | "FP";
  /** Representative code snippet for the case. */
  snippet: string;
  language: string;
}

export interface FpSourceAdapter {
  /** Stable id: "gitleaks" | "cwe" | "semgrep" | "juliet". */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Ensure upstream data is available locally (clone/fetch into vendor/). */
  fetch(): Promise<void>;
  /** Parse fetched data into normalized FP patterns (may be empty). */
  parsePatterns(): Promise<NormalizedFpPattern[]>;
  /** Parse fetched data into CWE knowledge (may be empty). */
  parseCweKnowledge?(): Promise<NormalizedCweKnowledge[]>;
  /** Parse fetched data into labeled benchmark cases (may be empty). */
  parseBenchmarkCases?(): Promise<BenchmarkCaseInput[]>;
}

export interface SyncStats {
  source: string;
  parsed: number;
  patternsCreated: number;
  patternsUpdated: number;
  patternsSkipped: number;
  cweUpserted: number;
  benchmarkCases: number;
  errors: string[];
  durationMs: number;
}

export interface SyncOptions {
  /** Only run these source ids (default: all). */
  sources?: string[];
  /** Force re-parse/upsert even if checksum unchanged. */
  force?: boolean;
  /** Skip persisting benchmark cases. */
  skipBenchmark?: boolean;
}

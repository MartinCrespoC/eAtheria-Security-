/**
 * Analysis Module — Barrel Export
 *
 * Centralizes all vulnerability analysis exports:
 * - SAST engine (static application security testing)
 * - SCA engine (software composition analysis)
 * - DAST engine (dynamic application security testing)
 * - False positive detector
 * - SBOM generator (software bill of materials)
 * - Analysis trigger (orchestrates scan pipeline)
 */

// SAST engine
export { runSastAnalysis } from "./sast-engine";

// SCA engine
export { queryOsvApi, runScaAnalysis, parseDependencies } from "./sca-engine";

// DAST engine
export { runDastAnalysis } from "./dast-engine";

// False positive detector
export { FalsePositiveDetector, falsePositiveDetector } from "./false-positive-detector";
export type { VulnerabilityMatch, FalsePositiveResult } from "./false-positive-detector";

// SBOM generator
export { generateSbom, generateSbomJson } from "./sbom-generator";

// Analysis trigger
export { triggerAnalysis, gatherSourceCode } from "./trigger";
export type { SourceCodeBundle } from "./trigger";

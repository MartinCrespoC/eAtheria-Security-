/**
 * Methodology Module — Barrel Exports
 * Codex-security knowledge replicated as provider-agnostic TypeScript
 */

// Severity Calibration Engine
export {
  SEVERITY_MATRIX,
  SEVERITY_TO_PRIORITY,
  SUPPRESSION_RULES,
  HIGH_CRITICAL_CHECKLIST,
  IMPACT_GUIDE,
  LIKELIHOOD_GUIDE,
  calibrateSeverity,
  buildSeverityAssessmentPrompt,
  parseSeverityAssessment,
  toAetheriaSeverity,
} from "./severity-calibration";
export type {
  ImpactLevel,
  LikelihoodLevel,
  CalibratedSeverityLevel,
  CalibratedSeverity,
  SeverityCalibrationInput,
  SeverityAssessmentResult,
  SuppressionContext,
} from "./severity-calibration";

// Attack-Path Analysis
export {
  buildAttackPathPrompt,
  parseAttackPathResponse,
  toVulnerabilityUpdate,
} from "./attack-path";
export type { AttackPathResult, CodeEvidenceItem, VulnContext } from "./attack-path";

// Threat Model Generation
export {
  buildThreatModelPrompt,
  parseThreatModel,
  buildThreatModelContext,
  inferRepoCapabilities,
} from "./threat-model";
export type { ThreatModelData, RepoInfo } from "./threat-model";

// Validation Methodology
export {
  VALIDATION_METHODS,
  getMethodStrength,
  calibrateConfidence,
  confidenceToLabel,
  buildValidationRubric,
  buildValidationPrompt,
  parseValidationResponse,
  toValidationUpdate,
} from "./validation-rubric";
export type {
  ValidationMethod,
  ValidationDisposition,
  ValidationMethodDef,
  RubricCriterion,
  ValidationResult,
} from "./validation-rubric";

// Finding Triage
export {
  buildTriagePrompt,
  triageFindings,
  parseTriageResponse,
} from "./triage";
export type {
  TriageSourceType,
  TriageVerdict,
  TriageInput,
  TriageVerdictResult,
} from "./triage";

// Vulnerability Writeup
export { buildWriteupPrompt, generateWriteup } from "./writeup";
export type { WriteupContext } from "./writeup";

// Security Hardening
export {
  TRADEOFF_DIMENSIONS,
  buildHardeningPrompt,
  parseHardeningResponse,
  generateHardeningProposal,
} from "./hardening";
export type {
  FindingSummary,
  HardeningOption,
  HardeningOpportunity,
  HardeningProposalData,
  TradeoffDimension,
} from "./hardening";

// Cross-Scan Comparison
export {
  buildComparisonPrompt,
  parseComparisonResponse,
  compareScans,
} from "./scan-comparison";
export type {
  ScanFindingSummary,
  ComparisonMatch,
  ComparisonResult,
} from "./scan-comparison";

// SECURITY.md Guidance Gate
export {
  resolveSecurityMd,
  buildPolicyContext,
  buildSecurityPolicyPrompt,
  generateSecurityPolicy,
  scanForSecurityGuidance,
} from "./security-guidance";
export type { SecurityPolicy, ResolvedGuidance } from "./security-guidance";

// Shared Prompt Fragments
export {
  ANALYSIS_VOICE,
  SHARED_HARD_RULES,
  JSON_OUTPUT_CONTRACT,
  EVIDENCE_STRENGTH_GUIDE,
  SOURCE_CONTROL_SINK_FRAMEWORK,
  CONFIDENCE_SCALE,
  truncateForPrompt,
  formatFindingContext,
} from "./prompts";

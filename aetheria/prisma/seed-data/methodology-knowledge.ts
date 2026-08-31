/**
 * Methodology Knowledge Seed Data
 * Severity calibration matrix, validation method hierarchy, and suppression rules
 * Stored as SystemConfig entries for admin-editable runtime configuration
 */

export const METHODOLOGY_CONFIGS: Array<{ key: string; value: unknown }> = [
  {
    key: "methodology_severity_matrix",
    value: {
      high: { high: "critical", medium: "high", low: "medium", ignore: "ignore" },
      medium: { high: "high", medium: "medium", low: "low", ignore: "ignore" },
      low: { high: "medium", medium: "low", low: "low", ignore: "ignore" },
      ignore: { high: "ignore", medium: "ignore", low: "ignore", ignore: "ignore" },
    },
  },
  {
    key: "methodology_suppression_rules",
    value: [
      {
        id: "self_only",
        result: "ignore",
        reason: "Only affects the attacker's own session/data",
        examples: ["Self-XSS requiring user to modify own DOM", "Changing own profile fields"],
      },
      {
        id: "unachievable_precondition",
        result: "ignore",
        reason: "Required precondition cannot be met in any supported deployment",
        examples: ["Requires physical access to air-gapped system", "Needs disabled ASLR + debug symbols"],
      },
      {
        id: "privileged_only",
        result: "ignore",
        reason: "Requires admin/root — same privilege as impact",
        examples: ["Admin can read other admin's config (same trust level)", "Root can ptrace any process"],
      },
      {
        id: "test_only_code",
        result: "ignore",
        reason: "Vulnerability exists only in test/demo code not shipped to production",
        examples: ["Hardcoded creds in test fixture", "Intentional vuln in CTF challenge"],
      },
      {
        id: "deprecated_unreachable",
        result: "ignore",
        reason: "Code is deprecated and no call path reaches it",
        examples: ["Dead function with no imports", "Commented-out route handler"],
      },
    ],
  },
  {
    key: "methodology_validation_methods",
    value: [
      { method: "crash_poc", strength: 1.0, description: "Crashing proof-of-concept demonstrating the vulnerability" },
      { method: "valgrind_asan", strength: 0.9, description: "Memory sanitizer (valgrind/ASan) evidence of unsafe access" },
      { method: "debugger_trace", strength: 0.8, description: "Non-interactive debugger trace showing source-to-sink path" },
      { method: "unit_test", strength: 0.7, description: "Focused regression test exercising the vulnerable code" },
      { method: "interface_repro", strength: 0.6, description: "Minimal end-to-end reproduction through real interface" },
      { method: "code_understanding", strength: 0.3, description: "Static code trace: source, control, sink, reachability analysis" },
    ],
  },
  {
    key: "methodology_severity_priority_map",
    value: {
      critical: "P0",
      high: "P1",
      medium: "P2",
      low: "P3",
      ignore: null,
    },
  },
  {
    key: "methodology_attack_path_enabled",
    value: true,
  },
  {
    key: "methodology_threat_model_enabled",
    value: true,
  },
  {
    key: "methodology_validation_enrichment_enabled",
    value: true,
  },
  {
    key: "methodology_max_attack_path_findings",
    value: 40,
  },
  {
    key: "methodology_scan_level_gating",
    value: {
      STATIC: { threatModel: false, attackPath: false, validation: false },
      LIGHTWEIGHT: { threatModel: true, attackPath: true, validation: false, minSeverity: "MEDIUM" },
      DEEP: { threatModel: true, attackPath: true, validation: true, minSeverity: "LOW" },
    },
  },
];

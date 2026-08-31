/**
 * FP Knowledge System — gitleaks adapter.
 *
 * gitleaks ships a curated TOML config of secret-detection rules. Each rule
 * (and the global scope) may carry an `[allowlist]` of regexes that match
 * secret-looking values that are KNOWN-SAFE (placeholders, examples, test keys,
 * documentation strings). Those allowlist regexes are exactly the high-precision
 * false-positive signals we want for hardcoded-secret findings (CWE-798/321/259).
 *
 * We extract ONLY allowlist regexes (never the detection regexes, which are
 * true-positive signals). Paths/stopwords are skipped: paths don't match code
 * snippets and bare stopwords over-match. Every regex is validated upstream by
 * the orchestrator before insert.
 */
import * as fs from "fs";
import * as path from "path";
import { parse } from "smol-toml";
import { VENDOR_ROOT, ensureHttpFile } from "../orchestrator";
import type { FpSourceAdapter, NormalizedFpPattern } from "../types";

const GITLEAKS_TOML_URL =
  "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml";
const CACHE_PATH = path.join(VENDOR_ROOT, "gitleaks", "gitleaks.toml");

const SECRET_CWES = ["CWE-798", "CWE-321", "CWE-259"];

interface GitleaksAllowlist {
  description?: string;
  regexes?: string[];
  paths?: string[];
  stopwords?: string[];
  condition?: string;
}

interface GitleaksRule {
  id: string;
  description?: string;
  regex?: string;
  tags?: string[];
  allowlist?: GitleaksAllowlist;
}

interface GitleaksConfig {
  title?: string;
  allowlist?: GitleaksAllowlist;
  rules?: GitleaksRule[];
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

export class GitleaksAdapter implements FpSourceAdapter {
  id = "gitleaks";
  name = "gitleaks (secret allowlists)";

  async fetch(): Promise<void> {
    await ensureHttpFile(GITLEAKS_TOML_URL, CACHE_PATH);
  }

  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    const raw = fs.readFileSync(CACHE_PATH, "utf8");
    const config = parse(raw) as unknown as GitleaksConfig;
    const patterns: NormalizedFpPattern[] = [];

    const pushAllowlist = (scope: string, label: string, allowlist?: GitleaksAllowlist) => {
      if (!allowlist) return;
      const regexes = asStringArray(allowlist.regexes);
      regexes.forEach((regex, idx) => {
        patterns.push({
          language: "*",
          pattern: regex,
          description: `gitleaks allowlist (${label}): safe secret-looking value`,
          reason:
            "This value matches gitleaks' curated allowlist of secret-looking strings that are known-safe " +
            "(placeholders, examples, test/documentation keys). A hardcoded-secret finding matching it is a false positive.",
          context: allowlist.description ?? null,
          cweIds: [...SECRET_CWES],
          examples: [],
          source: "gitleaks",
          sourceRuleId: `allowlist-${scope}-${idx}`,
          confidence: 90,
          category: "secret",
        });
      });
    };

    // Global allowlist applies to every rule.
    pushAllowlist("global", "global", config.allowlist);

    // Per-rule allowlists.
    for (const rule of config.rules ?? []) {
      if (!rule.id) continue;
      const label = rule.description ? `${rule.id} — ${rule.description}` : rule.id;
      pushAllowlist(rule.id, label, rule.allowlist);
    }

    return patterns;
  }
}

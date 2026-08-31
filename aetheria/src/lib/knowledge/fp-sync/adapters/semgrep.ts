/**
 * FP Knowledge System — Semgrep adapter.
 *
 * The Semgrep Registry (github.com/semgrep/semgrep-rules) encodes expert
 * detection rules in YAML with rich metadata: `metadata.cwe`, `metadata.precision`,
 * `metadata.confidence`, and `pattern-not` clauses that describe constructs which
 * LOOK vulnerable but are NOT (i.e. false positives).
 *
 * IMPORTANT: Semgrep `pattern`/`pattern-not` are AST patterns (with `$METAVAR`
 * and `...` ellipsis), NOT regular expressions. We therefore:
 *   (a) use them as KNOWLEDGE — aggregating per-CWE "DO NOT FLAG" guidance for
 *       the AI prompt and `commonFalsePositives` for the detector context; and
 *   (b) only promote a `pattern-not` to a real regex FP pattern when it is a
 *       plain literal (no metavariables/ellipsis) AND compiles as a RegExp.
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { VENDOR_ROOT, ensureGitRepo, isValidRegex } from "../orchestrator";
import type {
  FpSourceAdapter,
  NormalizedCweKnowledge,
  NormalizedFpPattern,
} from "../types";

const SEMGREP_REPO_URL = "https://github.com/semgrep/semgrep-rules.git";
const SEMGREP_DIR = path.join(VENDOR_ROOT, "semgrep");

/** Map a Semgrep language id to our internal language key. */
function mapLanguage(lang: string): string {
  const l = lang.toLowerCase();
  const map: Record<string, string> = {
    js: "javascript",
    javascript: "javascript",
    ts: "typescript",
    typescript: "typescript",
    python: "python",
    python2: "python",
    python3: "python",
    java: "java",
    kotlin: "kotlin",
    scala: "scala",
    go: "go",
    golang: "go",
    ruby: "ruby",
    php: "php",
    c: "c",
    "c++": "cpp",
    cpp: "cpp",
    csharp: "csharp",
    "c#": "csharp",
    rust: "rust",
    swift: "swift",
  };
  return map[l] ?? l;
}

function precisionToConfidence(precision: unknown): number {
  const p = String(precision ?? "").toUpperCase();
  if (p === "HIGH") return 85;
  if (p === "MEDIUM") return 75;
  if (p === "LOW") return 65;
  return 70;
}

/** Recursively collect every string value under any `pattern-not` key. */
function collectPatternNot(value: unknown, out: string[]): void {
  if (value == null) return;
  if (Array.isArray(value)) {
    for (const item of value) collectPatternNot(item, out);
    return;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === "pattern-not" || k === "pattern-not-regex" || k === "pattern-not-inside") {
        if (typeof v === "string") out.push(v);
        else collectPatternNot(v, out);
      } else {
        collectPatternNot(v, out);
      }
    }
  }
}

/** Extract CWE ids ("CWE-79") from Semgrep metadata.cwe (string | string[]). */
function extractCweIds(metadata: Record<string, unknown>): string[] {
  const ids = new Set<string>();
  for (const key of ["cwe", "cwe2021", "cwe2022"]) {
    const raw = metadata[key];
    const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
    for (const entry of list) {
      const s = typeof entry === "string" ? entry : JSON.stringify(entry ?? "");
      for (const m of s.matchAll(/CWE-\d+/g)) ids.add(m[0]);
    }
  }
  return [...ids];
}

/** True if a semgrep pattern is a plain literal usable as a regex (no AST sugar). */
function isPlainRegex(pattern: string): boolean {
  if (!pattern || pattern.length > 200) return false;
  if (pattern.includes("$") || pattern.includes("...")) return false;
  if (pattern.includes("<...>") || pattern.includes("...>")) return false;
  return isValidRegex(pattern);
}

interface SemgrepRule {
  id?: string;
  message?: string;
  languages?: string[];
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export class SemgrepAdapter implements FpSourceAdapter {
  id = "semgrep";
  name = "Semgrep Registry (CWE→FP knowledge)";

  async fetch(): Promise<void> {
    ensureGitRepo(SEMGREP_REPO_URL, SEMGREP_DIR);
  }

  /** Walk the repo and parse every YAML rule file. */
  private loadRules(): SemgrepRule[] {
    const rules: SemgrepRule[] = [];
    const stack: string[] = [SEMGREP_DIR];
    while (stack.length) {
      const dir = stack.pop()!;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === ".git") continue;
          stack.push(full);
        } else if (/\.(ya?ml)$/.test(ent.name)) {
          try {
            // JSON_SCHEMA is the strictest safe schema (no JS/custom tags),
            // which is sufficient for Semgrep rule YAML (maps/lists/scalars).
            const doc = yaml.load(fs.readFileSync(full, "utf8"), {
              schema: yaml.JSON_SCHEMA,
            }) as { rules?: SemgrepRule[] } | null;
            if (doc && Array.isArray(doc.rules)) {
              for (const r of doc.rules) if (r && typeof r === "object") rules.push(r);
            }
          } catch {
            // Ignore files that are not valid rule YAML.
          }
        }
      }
    }
    return rules;
  }

  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    const patterns: NormalizedFpPattern[] = [];
    for (const rule of this.loadRules()) {
      const metadata = rule.metadata ?? {};
      const cweIds = extractCweIds(metadata);
      if (!cweIds.length) continue; // Only security rules with CWE mapping are useful.
      const lang = mapLanguage((rule.languages ?? [])[0] ?? "*");
      const confidence = precisionToConfidence(metadata.precision ?? metadata.confidence);

      const patternNots: string[] = [];
      collectPatternNot(rule, patternNots);

      patternNots.forEach((pn, idx) => {
        if (!isPlainRegex(pn)) return; // Skip AST patterns; keep only safe literals.
        patterns.push({
          language: lang,
          pattern: pn,
          description: `Semgrep pattern-not (${rule.id ?? "rule"}): known-safe construct`,
          reason:
            "Semgrep's curated rule explicitly excludes this construct via pattern-not, meaning experts consider it a false positive for the associated CWE.",
          context: typeof rule.message === "string" ? rule.message.slice(0, 240) : null,
          cweIds,
          examples: [],
          source: "semgrep",
          sourceRuleId: `${rule.id ?? "rule"}#pn${idx}`,
          confidence,
          category: "semgrep",
        });
      });
    }
    return patterns;
  }

  async parseCweKnowledge(): Promise<NormalizedCweKnowledge[]> {
    // Aggregate per-CWE: collect human-readable "safe construct" hints from
    // pattern-not clauses and the best precision seen, to guide the AI prompt.
    const byCwe = new Map<
      string,
      { notPatterns: Set<string>; ruleIds: Set<string>; confidence: number }
    >();

    for (const rule of this.loadRules()) {
      const metadata = rule.metadata ?? {};
      const cweIds = extractCweIds(metadata);
      if (!cweIds.length) continue;
      const confidence = precisionToConfidence(metadata.precision ?? metadata.confidence);

      const patternNots: string[] = [];
      collectPatternNot(rule, patternNots);

      for (const cwe of cweIds) {
        const entry =
          byCwe.get(cwe) ?? { notPatterns: new Set<string>(), ruleIds: new Set<string>(), confidence: 0 };
        if (rule.id) entry.ruleIds.add(rule.id);
        entry.confidence = Math.max(entry.confidence, confidence);
        for (const pn of patternNots) {
          // Keep guidance readable & bounded.
          if (pn.length <= 120 && entry.notPatterns.size < 12) entry.notPatterns.add(pn.trim());
        }
        byCwe.set(cwe, entry);
      }
    }

    const results: NormalizedCweKnowledge[] = [];
    for (const [cweId, entry] of byCwe) {
      const commonFalsePositives = [...entry.notPatterns];
      const doNotFlag: string[] = [];
      if (commonFalsePositives.length) {
        doNotFlag.push(
          `${cweId}: do NOT flag constructs matching these Semgrep-vetted safe patterns: ${commonFalsePositives
            .slice(0, 6)
            .join(" | ")}`
        );
      }
      results.push({
        cweId,
        name: cweId, // Name enriched by the CWE adapter (union on upsert).
        category: "semgrep",
        commonFalsePositives,
        doNotFlag,
        detectionMethods: [],
        mitigations: [],
        source: "semgrep",
      });
    }
    return results;
  }
}

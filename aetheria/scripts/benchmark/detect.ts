/**
 * Shared deterministic detection primitive for the industry-standard benchmarks.
 *
 * Composes AETHERIA's deterministic engines — taint tracking, secrets detection
 * and IaC misconfiguration scanning — with DB-loaded rules, then pipes every raw
 * finding through the false-positive filter (`falsePositiveDetector`). The result
 * is the exact set of findings the platform would *report* for a snippet of code.
 *
 * This is the single detection primitive that every detection benchmark
 * (OpenSSF CVE Benchmark, OWASP Benchmark, WSTG-derived cases) calls, so all of
 * them measure the same pipeline and their scores are comparable.
 *
 * Deterministic engines are free/fast, which is what lets us run thousands of
 * cases. On top of them, `withAi` enables the AI verifier layer
 * (`src/lib/analysis/ai-verifier.ts`): LLM re-examination of kept findings
 * (anti-FP) and signal-gated missed-flow hunting (anti-FN), using full
 * project context when available. Without a configured provider the layer is
 * a no-op and the deterministic pipeline is the fallback.
 */
import { prisma } from "../../src/lib/db";
import {
  runSecretsDetection,
  type DbSecretPattern,
} from "../../src/lib/analysis/engines/secrets-engine";
import {
  runTaintAnalysis,
  type TaintRulesBundle,
} from "../../src/lib/analysis/engines/taint-engine";
import { runIacAnalysis, type DbIacRule } from "../../src/lib/analysis/engines/iac-engine";
import { runWeaknessAnalysis } from "../../src/lib/analysis/engines/weakness-engine";
import { falsePositiveDetector } from "../../src/lib/analysis/false-positive-detector";
import { evaluateFindingWithProject } from "../../src/lib/analysis/engines/project-context";
import {
  challengeFindingWithAi,
  huntMissedFlowsWithAi,
  verifyFindingWithAi,
  type AiChatFn,
} from "../../src/lib/analysis/ai-verifier";
import { createAiChatFromEnv } from "./ai-client";
import type { ScanLevel } from "../../src/lib/analysis/scan-knowledge";

/** A single finding produced by the detection pipeline for a code snippet. */
export interface DetectionOutcome {
  cweId: string;
  category: string;
  file: string;
  line: number;
  snippet: string;
  severity: string;
  title: string;
  confidence: number;
  detectionMethod: string; // TAINT | SECRET | IAC
  /** true = kept by the FP filter (would be reported); false = dismissed as FP. */
  kept: boolean;
  /** FP-filter confidence (0-100) for the keep/dismiss decision. */
  fpConfidence?: number;
  /** Reason from the matched FP pattern, when dismissed. */
  fpReason?: string;
  /** Taint-only: provenance kind of the tainted value. */
  source?: string;
  /** Taint-only: human-readable flow steps from source to sink. */
  taintPath?: string[];
}

export interface DetectInput {
  fileContent: string;
  filePath: string;
  language: string;
  scanLevel?: ScanLevel; // defaults to STATIC
  withAi?: boolean; // reserved; see module docstring (no-op in standalone mode)
  /**
   * Full project context: `relativePosixPath → content` for every scannable
   * file of the project under analysis (the file itself included). When
   * present, cross-file resolution (module graph, function summaries, project
   * -level sanitization) enriches detection; when absent, behavior is exactly
   * the legacy single-file analysis.
   */
  projectFiles?: Map<string, string> | null;
}

/** Normalized shape shared by the three deterministic engine outputs. */
interface RawFinding {
  cwe: string;
  category: string;
  severity: string;
  title: string;
  filePath: string;
  lineStart: number;
  codeSnippet: string;
  confidence: number;
  detectionMethod: string;
  /** Taint-only: provenance kind of the tainted value. */
  source?: string;
  /** Taint-only: human-readable flow steps from source to sink. */
  taintPath?: string[];
}

interface RulesCache {
  taint: TaintRulesBundle;
  secrets: DbSecretPattern[];
  iac: DbIacRule[];
}

let rulesCache: RulesCache | null = null;
let warnedNoAi = false;

/** Bounded AI usage per file: cost control at benchmark scale. */
const MAX_AI_VERIFICATIONS_PER_FILE = 8;
const MAX_AI_HUNT_CWES = 6;
const AI_CONCURRENCY = 4;
/** Verdict confidence thresholds for the AI layer. */
const FP_DISMISS_CONFIDENCE = 90;
const FP_CHALLENGE_CONFIDENCE = 80;
const TP_ACCEPT_CONFIDENCE = 60;
/** Hunted flows for CWEs without a DB sink need a stricter acceptance bar. */
const TP_ACCEPT_NO_SINK_CONFIDENCE = 75;

/** Run an async mapper with bounded concurrency. */
async function mapConcurrent<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

/** Load all active detection rules from the DB (cached for the process lifetime). */
export async function loadDetectionRules(): Promise<RulesCache> {
  if (rulesCache) return rulesCache;
  const [sources, sinks, sanitizers, secrets, iac] = await Promise.all([
    prisma.taintSource.findMany({ where: { isActive: true }, select: { language: true, pattern: true } }),
    prisma.taintSink.findMany({
      where: { isActive: true },
      select: { language: true, pattern: true, cwe: true, category: true, severity: true, owasp2021: true },
    }),
    prisma.taintSanitizer.findMany({ where: { isActive: true }, select: { language: true, pattern: true } }),
    prisma.secretPattern.findMany({
      where: { isActive: true },
      select: { ruleId: true, name: true, regex: true, severity: true, cwe: true, description: true },
    }),
    prisma.iacRule.findMany({
      where: { isActive: true },
      select: {
        ruleId: true,
        name: true,
        pattern: true,
        severity: true,
        cwe: true,
        category: true,
        description: true,
        fileTypes: true,
        framework: true,
      },
    }),
  ]);
  rulesCache = { taint: { sources, sinks, sanitizers }, secrets, iac };
  return rulesCache;
}

/**
 * Run the full deterministic detection pipeline over a single snippet/file and
 * return every finding annotated with whether the FP filter kept it.
 *
 * The set the platform would actually report is `outcomes.filter(o => o.kept)`.
 */
export async function detectInCode(input: DetectInput): Promise<DetectionOutcome[]> {
  const { fileContent, filePath, language, scanLevel = "STATIC", withAi = false, projectFiles } = input;

  let aiChat: AiChatFn | null = null;
  if (withAi) {
    aiChat = createAiChatFromEnv();
    if (!aiChat && !warnedNoAi) {
      warnedNoAi = true;
      console.warn(
        "   ⚠ --with-ai: no AI provider configured (set GOOGLE_API_KEY / OPENAI_API_KEY / AI_VERIFIER_API_KEY);\n" +
          "     running the deterministic engines only."
      );
    }
  }

  const rules = await loadDetectionRules();

  // Run the deterministic engines and normalize to a common shape. The weakness
  // engine covers non-taint weaknesses (weak crypto/hash/PRNG, insecure cookies,
  // trust-boundary) across languages — categories the taint engine cannot see.
  const raw: RawFinding[] = [
    ...(runTaintAnalysis(fileContent, filePath, language, rules.taint) as RawFinding[]),
    ...(runSecretsDetection(fileContent, filePath, rules.secrets) as RawFinding[]),
    ...(runIacAnalysis(fileContent, filePath, rules.iac) as RawFinding[]),
    ...(runWeaknessAnalysis(fileContent, filePath, language, rules.taint) as RawFinding[]),
  ];

  const outcomes: DetectionOutcome[] = [];
  const seen = new Set<string>();

  for (const f of raw) {
    // Collapse duplicate hits on the same CWE + line (different engines/methods).
    const key = `${f.cwe}|${f.lineStart}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const fp = await falsePositiveDetector.checkVulnerability({
      cweId: f.cwe,
      code: f.codeSnippet,
      codeSnippet: f.codeSnippet,
      language,
      line: f.lineStart,
      file: f.filePath,
      severity: f.severity,
      scanLevel,
    });

    outcomes.push({
      cweId: f.cwe,
      category: f.category,
      file: f.filePath,
      line: f.lineStart,
      snippet: f.codeSnippet,
      severity: f.severity,
      title: f.title,
      confidence: f.confidence,
      detectionMethod: f.detectionMethod,
      kept: !fp.isFalsePositive,
      fpConfidence: fp.confidence,
      fpReason: fp.matchedPattern?.reason,
      source: f.source,
      taintPath: f.taintPath,
    });
  }

  // Project-context post-processing (opt-in): when the full project tree is
  // available, cross-file call-site analysis can prove that an exported
  // function's tainted parameter is only ever reached with sanitized or
  // constant data — the semantic shape of most real-world patches (validation
  // added at the call site, often in another file). Suppressed findings get an
  // auditable fpReason.
  if (projectFiles && projectFiles.size > 0) {
    const sanitizers = rules.taint.sanitizers
      .filter((s) => s.language === language || s.language === "*")
      .map((s) => s.pattern);
    const sources = rules.taint.sources
      .filter((s) => s.language === language || s.language === "*")
      .map((s) => s.pattern);
    for (const o of outcomes) {
      if (!o.kept) continue;
      const verdict = evaluateFindingWithProject({
        detectionMethod: o.detectionMethod,
        source: o.source,
        taintPath: o.taintPath,
        filePath,
        fileContent,
        projectFiles,
        sanitizers,
        sources,
      });
      if (verdict.suppress) {
        o.kept = false;
        o.fpReason = verdict.reason;
      }
    }
  }

  // ── AI verifier layer (opt-in, provider-gated) ──
  if (aiChat) {
    // 1. Anti-FP: re-examine kept findings with full project context. Scope:
    //    TAINT flows only — the LLM adds value judging flow semantics ("is the
    //    input validated on the path?"), while structural findings (ReDoS,
    //    weak crypto) are mathematical judgments where the deterministic
    //    analyzer is strictly more reliable.
    const kept = outcomes
      .filter((o) => o.kept && (o.detectionMethod === "TAINT" || o.detectionMethod === "AI-SAST"))
      .slice(0, MAX_AI_VERIFICATIONS_PER_FILE);
    await mapConcurrent(kept, AI_CONCURRENCY, async (o) => {
      const verdict = await verifyFindingWithAi(
        {
          cweId: o.cweId,
          category: o.category,
          severity: o.severity,
          title: o.title,
          file: o.file,
          line: o.line,
          snippet: o.snippet,
          source: o.source,
          taintPath: o.taintPath,
          fileContent,
          projectFiles,
        },
        aiChat,
      );
      if (!verdict || verdict.verdict !== "fp") return;
      if (verdict.confidence >= FP_DISMISS_CONFIDENCE) {
        // High-confidence dismissal: no second pass needed.
        o.kept = false;
        o.fpReason = `AI verifier (${verdict.confidence}%): ${verdict.reason}`;
      } else if (verdict.confidence >= FP_CHALLENGE_CONFIDENCE) {
        // Borderline dismissal: require the adversarial fact-check to agree.
        const confirmed = await challengeFindingWithAi(
          {
            cweId: o.cweId,
            category: o.category,
            severity: o.severity,
            title: o.title,
            file: o.file,
            line: o.line,
            snippet: o.snippet,
            source: o.source,
            taintPath: o.taintPath,
            fileContent,
            projectFiles,
          },
          verdict.reason,
          aiChat,
        );
        if (confirmed && confirmed.verdict === "fp") {
          o.kept = false;
          o.fpReason = `AI verifier (${verdict.confidence}%, confirmed): ${verdict.reason}`;
        }
      }
    });

    // 2. Anti-FN: signal-gated missed-flow hunting. The gate is generic:
    //    the file contains tokens of DB sink patterns whose CWE has no kept
    //    finding, plus at least one DB source token.
    const keptCwes = new Set(outcomes.filter((o) => o.kept).map((o) => o.cweId.toUpperCase()));
    const fileLines = fileContent.split("\n");
    const langSinks = rules.taint.sinks.filter((s) => s.language === language || s.language === "*");
    const langSources = rules.taint.sources.filter((s) => s.language === language || s.language === "*");
    const hasSource = langSources.some((s) => fileContent.includes(s.pattern));
    if (hasSource) {
      const flows = await huntMissedFlowsWithAi(
        fileContent,
        filePath,
        [...keptCwes].slice(0, MAX_AI_HUNT_CWES),
        aiChat,
      );
      for (const flow of flows) {
        // The LLM proposes, the rules dispose: when the claimed CWE has a DB
        // sink, the cited sink line must match it; otherwise (validation-class
        // CWEs without taint sinks) the flow needs distinct in-file lines and
        // passes a stricter verification bar.
        const sinkRule = langSinks.find((s) => s.cwe.toUpperCase() === flow.cweId.toUpperCase());
        if (sinkRule) {
          let sinkRegex: RegExp;
          try {
            sinkRegex = new RegExp(sinkRule.pattern);
          } catch {
            continue;
          }
          const citedLine = fileLines[flow.sinkLine - 1] ?? "";
          const near = fileLines.slice(Math.max(0, flow.sinkLine - 3), flow.sinkLine + 2).join("\n");
          if (!sinkRegex.test(citedLine) && !sinkRegex.test(near)) continue;
        } else {
          if (flow.sinkLine === flow.sourceLine) continue;
          if (flow.sinkLine < 1 || flow.sinkLine > fileLines.length) continue;
          if (flow.sourceLine < 1 || flow.sourceLine > fileLines.length) continue;
        }
        // The candidate then passes the same verifier as any other finding.
        const snippet = fileLines.slice(Math.max(0, flow.sinkLine - 4), flow.sinkLine + 2).join("\n");
        const category = sinkRule?.category ?? flow.cweId;
        const severity = sinkRule?.severity ?? "HIGH";
        const title = `${category}: ${flow.cweId} in ${filePath.split("/").pop()} (AI-detected)`;
        const verdict = await verifyFindingWithAi(
          {
            cweId: flow.cweId,
            category,
            severity,
            title,
            file: filePath,
            line: flow.sinkLine,
            snippet,
            taintPath: [
              `AI-detected flow: source line ${flow.sourceLine}`,
              `SINK: ${sinkRule?.pattern ?? flow.cweId} (line ${flow.sinkLine}) — ${flow.explanation}`,
            ],
            fileContent,
            projectFiles,
          },
          aiChat,
        );
        const acceptBar = sinkRule ? TP_ACCEPT_CONFIDENCE : TP_ACCEPT_NO_SINK_CONFIDENCE;
        if (!verdict || verdict.verdict !== "tp" || verdict.confidence < acceptBar) continue;
        outcomes.push({
          cweId: flow.cweId,
          category,
          file: filePath,
          line: flow.sinkLine,
          snippet,
          severity,
          title,
          confidence: verdict.confidence,
          detectionMethod: "AI-SAST",
          kept: true,
          source: "ai-hunted",
          taintPath: [
            `AI-detected flow: source line ${flow.sourceLine}`,
            `SINK: ${sinkRule?.pattern ?? flow.cweId} (line ${flow.sinkLine}) — ${flow.explanation}`,
          ],
        });
      }
    }
  }

  return outcomes;
}

/** Convenience: the subset of outcomes the platform would actually report. */
export function keptFindings(outcomes: DetectionOutcome[]): DetectionOutcome[] {
  return outcomes.filter((o) => o.kept);
}

/** True if any kept finding matches the given CWE id (case-insensitive). */
export function hasKeptFindingForCwe(outcomes: DetectionOutcome[], cweId: string): boolean {
  const target = cweId.toUpperCase();
  return outcomes.some((o) => o.kept && o.cweId.toUpperCase() === target);
}

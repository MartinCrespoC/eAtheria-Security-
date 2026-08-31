/**
 * AI verifier — LLM-based verification layer for the detection pipeline.
 *
 * Two capabilities, both generic (no benchmark knowledge, no expected-CWE
 * hints — the model only ever sees code and the pipeline's own output):
 *
 * 1. Finding verification (anti-FP): every kept deterministic finding is
 *    re-examined with full project context (taint path, snippet, callers).
 *    The model judges whether the flow is a real, reachable vulnerability.
 *    Verdicts of "fp" with sufficient confidence dismiss the finding with an
 *    auditable reason. This is what resolves semantic twins: patches whose
 *    fix is data-level (a check that only excludes the exploit input) leave
 *    the syntactic flow intact, and only semantic judgement can tell them
 *    apart.
 *
 * 2. Missed-flow hunting (anti-FN), signal-gated: files that contain both
 *    taint-source and sink tokens but produced no kept finding for that sink
 *    CWE are reviewed once. Candidate findings must cite concrete source and
 *    sink lines; they are accepted only when the cited sink line matches a DB
 *    sink pattern for the claimed CWE and then pass through the same finding
 *    verifier. The LLM proposes, the rules dispose.
 *
 * Determinism & cost: temperature 0 callers, verdicts cached by SHA-256 of
 * the evidence pack (re-runs are free), JSON responses, token caps. Without
 * a chat function the layer is a no-op — the deterministic pipeline is the
 * always-available fallback.
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import {
  untrustedBoundary,
  wrapUntrusted,
  untrustedDataRules,
  detectInjectionMarkers,
  injectionWarning,
} from "../ai/prompt-guard";

/** Injected chat function: system+user prompt → assistant text. */
export type AiChatFn = (input: {
  system: string;
  user: string;
  maxTokens?: number;
}) => Promise<string>;

export interface AiVerdict {
  verdict: "tp" | "fp" | "uncertain";
  confidence: number; // 0-100
  reason: string;
}

export interface VerifyFindingInput {
  cweId: string;
  category: string;
  severity: string;
  title: string;
  file: string;
  line: number;
  snippet: string;
  source?: string;
  taintPath?: string[];
  /** Full content of the analyzed file (for caller context windows). */
  fileContent?: string;
  /** Project files for cross-file caller evidence (path → content). */
  projectFiles?: Map<string, string> | null;
}

export interface HuntedFlow {
  cweId: string;
  sinkLine: number;
  sourceLine: number;
  explanation: string;
}

// ─────────────────────────────── verdict cache ───────────────────────────────

const CACHE_DIR = path.join(process.cwd(), "vendor", "cache", "ai-verifier");
let diskCache: Map<string, unknown> | null = null;

function loadCache(): Map<string, unknown> {
  if (diskCache) return diskCache;
  diskCache = new Map();
  try {
    const file = path.join(CACHE_DIR, "verdicts.json");
    if (fs.existsSync(file)) {
      const raw = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
      for (const [k, v] of Object.entries(raw)) diskCache.set(k, v);
    }
  } catch {
    /* corrupt cache → start fresh */
  }
  return diskCache;
}

let cacheDirty = false;
let dirtyCount = 0;
function cacheSet(key: string, value: unknown): void {
  loadCache().set(key, value);
  cacheDirty = true;
  // Persist periodically: long benchmark runs must survive interruption.
  if (++dirtyCount % 50 === 0) flushAiVerifierCache();
}

/** Persist the verdict cache (call once at the end of a run). */
export function flushAiVerifierCache(): void {
  if (!cacheDirty || !diskCache) return;
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(CACHE_DIR, "verdicts.json"),
      JSON.stringify(Object.fromEntries(diskCache), null, 1),
    );
    cacheDirty = false;
  } catch {
    /* cache write failures are non-fatal */
  }
}

function hashOf(parts: unknown[]): string {
  return crypto.createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 32);
}

/** Bumped when prompt templates change — part of every cache key so prompt
 *  iterations never reuse stale verdicts. */
const PROMPT_VERSION = 3;

/** Model identity is part of every cache key — verdicts from different
 *  models must never be mixed. */
const MODEL_TAG = process.env.AI_VERIFIER_MODEL ?? "gemini-2.5-flash";

/** Bumped when hunt parsing/prompt logic changes (independent of verify). */
const HUNT_VERSION = 2;

// ─────────────────────────────── prompt building ─────────────────────────────

const SYSTEM = `You are a senior application-security engineer reviewing findings from a static analysis tool (source→sink taint analysis). You are precise and conservative: you only dismiss a finding when the code clearly shows the flow is NOT exploitable, and you only confirm a missed vulnerability when you can cite the exact source and sink lines.

Hard rules for dismissal (verdict "fp"):
- You MUST quote the exact line(s) of code that neutralize the flow (validation, escaping, encoding, type check, or the proof the sink semantics are safe). If you cannot quote a concrete line, the verdict CANNOT be "fp" — use "uncertain".
- Severity/impact reasoning NEVER justifies dismissal ("low impact", "only local files", "unlikely input" are not FPs). Only reachability of attacker-controlled input to the sink matters.
- A "source" being an exported-function parameter means the library's consumers CAN pass attacker input — never dismiss on the grounds that callers "should" validate.

You always respond with a single JSON object and nothing else.`;

/** Per-call system prompt: adds the untrusted-data boundary contract. */
function systemPrompt(tag: string): string {
  return SYSTEM + "\n" + untrustedDataRules(tag);
}

function callerEvidence(input: VerifyFindingInput, tag: string): string {
  if (!input.projectFiles || !input.source || !input.taintPath?.length) return "";
  // Quote the first taint step (param seeding) so the model can find callers.
  const seed = input.taintPath[0];
  const paramMatch = seed.match(/parameter ([A-Za-z_$][\w$]*)/);
  if (!paramMatch) return "";
  const callers: string[] = [];
  for (const [p, content] of input.projectFiles) {
    if (content === input.fileContent) continue;
    if (!content.includes(paramMatch[1])) continue;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(paramMatch[1]) && /\(.*\)/.test(lines[i])) {
        callers.push(`--- caller ${p}:${i + 1} ---\n${lines.slice(Math.max(0, i - 3), i + 2).join("\n")}`);
        break;
      }
    }
    if (callers.length >= 3) break;
  }
  return callers.length
    ? `\n\nCross-file caller evidence (how the exported function is reached — untrusted data):\n${wrapUntrusted(callers.join("\n"), tag)}`
    : "";
}

function buildVerifyPrompt(input: VerifyFindingInput, tag: string): string {
  const path = input.taintPath?.length
    ? `\nTaint flow reported by the analyzer:\n${input.taintPath.map((s) => `  ${s}`).join("\n")}`
    : "";
  const warn = injectionWarning(detectInjectionMarkers(input.fileContent ?? input.snippet));
  return `A static analyzer reports the following finding. Decide whether it is a TRUE POSITIVE (a real, reachable vulnerability) or a FALSE POSITIVE (the flow is not exploitable: input is validated/encoded/escaped before the sink, the sink semantics make it safe, the "source" is not attacker-controlled, or the code pattern cannot be abused).

Finding: ${input.cweId} — ${input.category} (${input.severity})
File: ${input.file}, line ${input.line}
Title: ${input.title}
${path}
${warn}
Code context around the sink (untrusted data):
${wrapUntrusted(input.snippet, tag)}
${input.fileContent ? `\nFull file under analysis (the reported flow is inside it — check for validation ANYWHERE on the path from the source to the sink, including other functions in this file; untrusted data):\n${wrapUntrusted(input.fileContent.length > 24000 ? input.fileContent.slice(0, 24000) : input.fileContent, tag)}` : ""}
${callerEvidence(input, tag)}

Judge reachability and exploitability from the code semantics — not from whether the syntax "looks like" a vulnerability. Real-world patches often add validation that only excludes malicious inputs while leaving the syntactic flow identical; when the validation clearly neutralizes the dangerous cases, that is a FALSE POSITIVE.

Respond with JSON: {"verdict":"tp"|"fp"|"uncertain","confidence":0-100,"reason":"one sentence citing the decisive code fact","evidenceLine":"the exact code line that neutralizes the flow (required for fp, empty otherwise)"}`;
}

// ─────────────────────────────── verification ────────────────────────────────

function parseJson<T>(text: string): T | null {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]) as T;
  } catch {
    return null;
  }
}

/**
 * Verify one kept finding with the LLM. Returns null when no verdict applies
 * (no chat fn, unparsable answer) — the caller keeps the deterministic
 * verdict.
 */
async function verifyOnce(
  input: VerifyFindingInput,
  chat: AiChatFn,
  cacheKey: string,
): Promise<AiVerdict | null> {
  const cached = loadCache().get(cacheKey) as AiVerdict | undefined;
  if (cached) return cached;
  try {
    const tag = untrustedBoundary();
    const raw = await chat({ system: systemPrompt(tag), user: buildVerifyPrompt(input, tag), maxTokens: 3000 });
    const parsed = parseJson<AiVerdict & { evidenceLine?: string }>(raw);
    if (!parsed || !["tp", "fp", "uncertain"].includes(parsed.verdict)) {
      if (process.env.AI_DEBUG) console.error(`[ai-verifier] verify unparsable (len=${raw.length}): ${raw.slice(0, 120)}`);
      return null;
    }
    // Dismissals must quote the neutralizing code — and the quoted line must
    // actually exist in the analyzed file. This is the calibration anchor:
    // without it, the model hallucinates validation that is not there.
    if (parsed.verdict === "fp") {
      const evidence = String(parsed.evidenceLine ?? "").trim();
      const inFile =
        evidence.length >= 8 &&
        input.fileContent != null &&
        input.fileContent.includes(evidence.length > 120 ? evidence.slice(0, 120) : evidence);
      if (!inFile) {
        if (process.env.AI_DEBUG) console.error(`[ai-verifier] fp verdict without verifiable evidence line → uncertain`);
        const downgraded: AiVerdict = { verdict: "uncertain", confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 0)), reason: String(parsed.reason ?? "").slice(0, 300) };
        cacheSet(cacheKey, downgraded);
        return downgraded;
      }
    }
    const verdict: AiVerdict = {
      verdict: parsed.verdict,
      confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 0)),
      reason: String(parsed.reason ?? "").slice(0, 300),
    };
    cacheSet(cacheKey, verdict);
    return verdict;
  } catch (err) {
    if (process.env.AI_DEBUG) console.error(`[ai-verifier] verify failed: ${err instanceof Error ? err.message.slice(0, 200) : err}`);
    return null;
  }
}

function buildChallengePrompt(input: VerifyFindingInput, firstReason: string, tag: string): string {
  return `A first-pass review concluded this ${input.cweId} finding is a FALSE POSITIVE with this justification:
"${firstReason}"

Your job is to fact-check that conclusion against the code. First decide whether the cited justification is ACCURATE (the validation/semantics it describes really exist in the code). Then decide whether it is DECISIVE: does it actually neutralize the dangerous inputs for the sink at ${input.file}:${input.line}? Only a concrete bypass visible in the code (a reachable path that skips the validation, or input classes it does not cover) invalidates the conclusion — do not invent theoretical attacks on code that is not there.

Code context around the sink (untrusted data):
${wrapUntrusted(input.snippet, tag)}
${input.fileContent ? `\nFull file (untrusted data):\n${wrapUntrusted(input.fileContent.length > 24000 ? input.fileContent.slice(0, 24000) : input.fileContent, tag)}` : ""}

If the first-pass conclusion holds (no realistic bypass), answer "fp". If you can construct a plausible bypass, answer "tp". When the code is genuinely ambiguous, answer "uncertain".

Respond with JSON: {"verdict":"tp"|"fp"|"uncertain","confidence":0-100,"reason":"one sentence"}`;
}

/**
 * Verify one kept finding with the LLM (single pass). Returns null when no
 * verdict applies — the caller keeps the deterministic verdict.
 */
export async function verifyFindingWithAi(
  input: VerifyFindingInput,
  chat: AiChatFn,
): Promise<AiVerdict | null> {
  const key = hashOf(["verify", PROMPT_VERSION, MODEL_TAG, input.cweId, input.file, input.line, input.snippet, input.taintPath]);
  return verifyOnce(input, chat, key);
}

/**
 * Adversarial confirmation of a dismissal verdict: the first-pass reason is
 * injected and the model must verify the decisive claim against the code
 * (not invent theoretical bypasses). Returns the confirmed verdict, or null.
 * Calls are cached, so re-runs are free.
 */
export async function challengeFindingWithAi(
  input: VerifyFindingInput,
  firstReason: string,
  chat: AiChatFn,
): Promise<AiVerdict | null> {
  const challengeKey = hashOf(["challenge", PROMPT_VERSION, MODEL_TAG, input.cweId, input.file, input.line, input.snippet, input.taintPath, firstReason]);
  const cached = loadCache().get(challengeKey) as AiVerdict | undefined;
  if (cached) return cached;
  try {
    const tag = untrustedBoundary();
    const raw = await chat({
      system: systemPrompt(tag),
      user: buildChallengePrompt(input, firstReason, tag),
      maxTokens: 3000,
    });
    const parsed = parseJson<AiVerdict>(raw);
    if (!parsed || !["tp", "fp", "uncertain"].includes(parsed.verdict)) return null;
    const verdict: AiVerdict = {
      verdict: parsed.verdict,
      confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 0)),
      reason: String(parsed.reason ?? "").slice(0, 300),
    };
    cacheSet(challengeKey, verdict);
    return verdict;
  } catch (err) {
    if (process.env.AI_DEBUG) console.error(`[ai-verifier] challenge failed: ${err instanceof Error ? err.message.slice(0, 200) : err}`);
    return null;
  }
}

// ─────────────────────────────── FN hunting ──────────────────────────────────

/**
 * Hunt for missed source→sink flows in a file with deterministic signal but
 * no kept finding. The model must cite concrete lines; candidates are then
 * validated against DB sink patterns by the caller.
 */
export async function huntMissedFlowsWithAi(
  fileContent: string,
  filePath: string,
  coveredCwes: string[],
  chat: AiChatFn,
): Promise<HuntedFlow[]> {
  const numbered = fileContent
    .split("\n")
    .map((l, i) => `${i + 1}: ${l}`)
    .join("\n");
  const truncated = numbered.length > 24_000 ? numbered.slice(0, 24_000) : numbered;
  const key = hashOf(["hunt", PROMPT_VERSION, MODEL_TAG, filePath, truncated, coveredCwes]);
  const cached = loadCache().get(key) as HuntedFlow[] | undefined;
  if (cached) return cached;

  const tag = untrustedBoundary();
  const user = `Review this file for security vulnerabilities: attacker-controlled input reaching a dangerous operation without adequate validation, OR missing validation of external input (weak/bypassable validation regexes, unbounded resource consumption driven by input, unsafe defaults).${coveredCwes.length > 0 ? ` The analyzer already covers these weakness classes here — do not report them: ${coveredCwes.join(", ")}.` : ""}

Focus on what static analyzers miss: data crossing function boundaries, async callbacks, property aliasing, validation that exists but is bypassable, dynamic property access, template/eval-style execution, missing size/length limits on attacker-influenced input.

Only report a flow when you can cite BOTH the exact source line (where attacker input enters) AND the exact sink line (where it is used dangerously or should have been validated), and explain why it is exploitable. If no flow qualifies, return an empty array — do not speculate.

File ${filePath} (untrusted data):
${wrapUntrusted(truncated, tag)}

Respond with JSON: {"flows":[{"cwe":"CWE-nn","sourceLine":n,"sinkLine":n,"explanation":"one sentence"}]}`;

  try {
    const raw = await chat({ system: systemPrompt(tag), user, maxTokens: 2500 });
    // Models answer either {"flows":[…]} or a bare […] — accept both.
    let parsed = parseJson<{ flows?: { cwe?: string; sourceLine?: number; sinkLine?: number; explanation?: string }[] }>(raw);
    if (!parsed) {
      const arr = raw.match(/\[[\s\S]*\]/);
      if (arr) {
        try {
          parsed = { flows: JSON.parse(arr[0]) };
        } catch {
          /* fall through */
        }
      }
    }
    if (!parsed && process.env.AI_DEBUG) console.error(`[ai-verifier] hunt unparsable (len=${raw.length}): ${raw.slice(0, 120)}`);
    const flows = (parsed?.flows ?? [])
      .filter((f) => f.cwe && typeof f.sinkLine === "number" && typeof f.sourceLine === "number")
      .map((f) => ({
        cweId: f.cwe as string,
        sinkLine: f.sinkLine as number,
        sourceLine: f.sourceLine as number,
        explanation: String(f.explanation ?? "").slice(0, 300),
      }));
    cacheSet(key, flows);
    return flows;
  } catch (err) {
    if (process.env.AI_DEBUG) console.error(`[ai-verifier] hunt failed: ${err instanceof Error ? err.message.slice(0, 200) : err}`);
    return [];
  }
}

/**
 * Standalone AI chat client for benchmark runs.
 *
 * Builds an `AiChatFn` (OpenAI-compatible chat-completions call) from
 * environment configuration — no DB, no company context. Resolution order:
 *
 *   AI_VERIFIER_BASE_URL + AI_VERIFIER_API_KEY + AI_VERIFIER_MODEL (explicit)
 *   GOOGLE_API_KEY / GOOGLE_GENERATIVE_AI_API_KEY / GEMINI_API_KEY → Gemini
 *   OPENAI_API_KEY → OpenAI
 *   ANTHROPIC_API_KEY → Anthropic (via its OpenAI-compat endpoint)
 *
 * `.env` in the repo root is loaded manually (tsx does not auto-load it).
 * Returns null when nothing is configured — callers fall back to the
 * deterministic pipeline.
 */
import * as fs from "fs";
import * as path from "path";
import type { AiChatFn } from "../../src/lib/analysis/ai-verifier";

let envLoaded = false;

/** Minimal .env loader: KEY=VALUE lines, no interpolation, no overrides. */
function loadDotEnv(): void {
  if (envLoaded) return;
  envLoaded = true;
  const file = path.join(process.cwd(), ".env");
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    if (process.env[m[1]] !== undefined) continue; // real env wins
    let value = m[2];
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[m[1]] = value;
  }
}

interface ProviderSpec {
  baseUrl: string;
  apiKey: string;
  model: string;
}

function resolveProvider(): ProviderSpec | null {
  loadDotEnv();
  if (process.env.AI_VERIFIER_API_KEY) {
    return {
      baseUrl: process.env.AI_VERIFIER_BASE_URL ?? "https://generativelanguage.googleapis.com/v1beta/openai",
      apiKey: process.env.AI_VERIFIER_API_KEY,
      model: process.env.AI_VERIFIER_MODEL ?? "gemini-2.5-flash",
    };
  }
  const google =
    process.env.GOOGLE_API_KEY ??
    process.env.GOOGLE_GENERATIVE_AI_API_KEY ??
    process.env.GEMINI_API_KEY;
  if (google) {
    return {
      baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
      apiKey: google,
      model: process.env.AI_VERIFIER_MODEL ?? "gemini-2.5-flash",
    };
  }
  if (process.env.OPENAI_API_KEY) {
    return {
      baseUrl: "https://api.openai.com/v1",
      apiKey: process.env.OPENAI_API_KEY,
      model: process.env.AI_VERIFIER_MODEL ?? "gpt-4o-mini",
    };
  }
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      baseUrl: "https://api.anthropic.com/v1",
      apiKey: process.env.ANTHROPIC_API_KEY,
      model: process.env.AI_VERIFIER_MODEL ?? "claude-haiku-4-5-20251001",
    };
  }
  return null;
}

/** Create the chat function, or null when no provider is configured. */
export function createAiChatFromEnv(): AiChatFn | null {
  const spec = resolveProvider();
  if (!spec) return null;
  const RETRYABLE = new Set([429, 500, 502, 503, 504]);
  return async ({ system, user, maxTokens = 400 }) => {
    let lastErr: Error | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, attempt * 8000));
      }
      try {
        const res = await fetch(`${spec.baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${spec.apiKey}`,
          },
          body: JSON.stringify({
            model: spec.model,
            temperature: 0,
            max_tokens: maxTokens,
            // Thinking models (gemini-2.5): keep the reasoning budget small so
            // the JSON answer always fits in max_tokens. Providers that do
            // not know this field ignore it.
            reasoning_effort: "low",
            messages: [
              { role: "system", content: system },
              { role: "user", content: user },
            ],
          }),
        });
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          lastErr = new Error(`AI verifier HTTP ${res.status}: ${body.slice(0, 200)}`);
          if (RETRYABLE.has(res.status)) continue;
          throw lastErr;
        }
        const json = (await res.json()) as {
          choices?: { message?: { content?: string } }[];
        };
        return json.choices?.[0]?.message?.content ?? "";
      } catch (err) {
        lastErr = err instanceof Error ? err : new Error(String(err));
        if (!lastErr.message.startsWith("AI verifier HTTP")) continue; // network error → retry
        if (RETRYABLE.has(Number(lastErr.message.match(/HTTP (\d+)/)?.[1]))) continue;
        throw lastErr;
      }
    }
    throw lastErr ?? new Error("AI verifier failed after retries");
  };
}

/** Human-readable description of the resolved provider (for run metrics). */
export function describeAiProvider(): string | null {
  const spec = resolveProvider();
  return spec ? `${spec.baseUrl.split("/")[2]}:${spec.model}` : null;
}

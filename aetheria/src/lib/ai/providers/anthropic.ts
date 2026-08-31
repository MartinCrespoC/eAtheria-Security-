import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

const ANTHROPIC_API_URL = "https://api.anthropic.com";
const ANTHROPIC_VERSION = "2023-06-01";

export class AnthropicAdapter implements AIProviderAdapter {
  readonly type = "anthropic";

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const baseUrl = config.baseUrl || ANTHROPIC_API_URL;

    const messages: Array<{ role: string; content: string }> = [
      { role: "user", content: prompt },
    ];

    const body: Record<string, unknown> = {
      model: options.model,
      messages,
      max_tokens: options.maxOutputTokens ?? 8192,
      temperature: options.temperature ?? 0.7,
    };

    if (options.systemInstruction) {
      body.system = options.systemInstruction;
    }

    const response = await fetch(`${baseUrl}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": config.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[anthropic] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();

    const text = data.content
      ?.filter((b: { type: string }) => b.type === "text")
      .map((b: { text: string }) => b.text)
      .join("") || "";

    const inputTokens = data.usage?.input_tokens || 0;
    const outputTokens = data.usage?.output_tokens || 0;

    return {
      text,
      inputTokens,
      outputTokens,
      modelUsed: data.model || options.model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const baseUrl = config.baseUrl || ANTHROPIC_API_URL;

    try {
      const response = await fetch(`${baseUrl}/v1/models`, {
        headers: {
          "x-api-key": config.apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
        },
      });

      if (!response.ok) {
        // Anthropic might not have a /models endpoint — return static list
        return getStaticAnthropicModels();
      }

      const data = await response.json();
      const models = data.data || [];
      return models.map((m: { id: string; display_name?: string }) => ({
        modelId: m.id,
        displayName: m.display_name || m.id,
        description: "",
        inputTokenLimit: 200000,
        outputTokenLimit: 8192,
      }));
    } catch {
      return getStaticAnthropicModels();
    }
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const baseUrl = config.baseUrl || ANTHROPIC_API_URL;

    try {
      // Try a minimal request to verify the key
      const response = await fetch(`${baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": config.apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 1,
          messages: [{ role: "user", content: "hi" }],
        }),
      });

      // 200 = works, 400 = auth ok but bad request (also fine)
      if (response.ok || response.status === 400) return { ok: true };
      if (response.status === 401 || response.status === 403) {
        return { ok: false, error: "API key inválida o sin permisos" };
      }
      return { ok: true }; // other errors likely mean the key is fine
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

function getStaticAnthropicModels(): AIAvailableModel[] {
  return [
    { modelId: "claude-sonnet-4-20250514", displayName: "Claude Sonnet 4", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "claude-haiku-4-5-20251001", displayName: "Claude Haiku 4.5", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "claude-opus-4-20250514", displayName: "Claude Opus 4", inputTokenLimit: 200000, outputTokenLimit: 8192 },
  ];
}

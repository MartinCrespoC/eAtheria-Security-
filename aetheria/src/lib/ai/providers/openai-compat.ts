import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

// Fallback models for the /chat/completions key-validation path
// (providers without a public /models endpoint).
const DEFAULT_FALLBACK_MODELS: Record<string, string> = {
  perplexity: "sonar",
  nvidia: "meta/llama-3.1-8b-instruct",
};

const DEFAULT_URLS: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  deepseek: "https://api.deepseek.com",
  xai: "https://api.x.ai/v1",
  mistral: "https://api.mistral.ai/v1",
  nvidia: "https://integrate.api.nvidia.com/v1",
  perplexity: "https://api.perplexity.ai",
  qwen: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
  kimi: "https://api.moonshot.cn/v1",
  minimax: "https://api.minimax.chat/v1",
  huggingface: "https://api-inference.huggingface.co/v1",
};

export class OpenAICompatAdapter implements AIProviderAdapter {
  readonly type = "openai-compatible";

  constructor(private providerSlug?: string) {}

  private getBaseUrl(config: AIProviderConfig): string {
    if (config.baseUrl) return config.baseUrl.replace(/\/+$/, "");
    if (this.providerSlug && DEFAULT_URLS[this.providerSlug]) {
      return DEFAULT_URLS[this.providerSlug];
    }
    return "https://api.openai.com/v1";
  }

  private getHeaders(config: AIProviderConfig): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.apiKey}`,
    };

    // OpenRouter requires extra headers
    if (this.providerSlug === "openrouter") {
      headers["HTTP-Referer"] = "https://aetheria.io";
      headers["X-Title"] = "EATHERIA Security Platform";
    }

    // Merge any custom headers from config
    const customHeaders = config.config?.headers as Record<string, string> | undefined;
    if (customHeaders) {
      Object.assign(headers, customHeaders);
    }

    return headers;
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const baseUrl = this.getBaseUrl(config);
    const headers = this.getHeaders(config);

    const messages: Array<{ role: string; content: string }> = [];

    if (options.systemInstruction) {
      messages.push({ role: "system", content: options.systemInstruction });
    }
    messages.push({ role: "user", content: prompt });

    const body: Record<string, unknown> = {
      model: options.model,
      messages,
      temperature: options.temperature ?? 0.7,
      max_tokens: options.maxOutputTokens ?? 8192,
    };

    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[${this.providerSlug || "openai-compat"}] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const choice = data.choices?.[0];
    const text = choice?.message?.content || "";

    const usage = data.usage || {};
    const inputTokens = usage.prompt_tokens || 0;
    const outputTokens = usage.completion_tokens || 0;

    return {
      text,
      inputTokens,
      outputTokens,
      modelUsed: data.model || options.model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const baseUrl = this.getBaseUrl(config);
    const headers = this.getHeaders(config);
    delete headers["Content-Type"];

    try {
      const response = await fetch(`${baseUrl}/models`, { headers });
      if (!response.ok) return [];

      const data = await response.json();
      const models = data.data || data.models || [];

      return models.map((m: { id: string; name?: string; description?: string; context_length?: number }) => ({
        modelId: m.id,
        displayName: m.name || m.id,
        description: m.description || "",
        inputTokenLimit: m.context_length || 0,
        outputTokenLimit: 0,
      }));
    } catch {
      return [];
    }
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const baseUrl = this.getBaseUrl(config);
    const headers = this.getHeaders(config);

    try {
      const modelListHeaders = { ...headers };
      delete modelListHeaders["Content-Type"];
      const response = await fetch(`${baseUrl}/models`, { headers: modelListHeaders });
      if (response.ok) return { ok: true };
      // Some providers (e.g. Perplexity) don't expose /models — fall back to a
      // minimal chat completion to validate the key.
      if (response.status === 404) {
        const model = DEFAULT_FALLBACK_MODELS[this.providerSlug || ""] || "sonar";
        const chat = await fetch(`${baseUrl}/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: "ping" }],
            max_tokens: 1,
          }),
        });
        if (chat.ok) return { ok: true };
        const chatErr = await chat.text();
        return { ok: false, error: `HTTP ${chat.status}: ${chatErr.substring(0, 200)}` };
      }
      const errText = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${errText.substring(0, 200)}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

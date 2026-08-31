import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

const COPILOT_BASE_URL = "https://api.githubcopilot.com";
const COPILOT_EDITOR_VERSION = "vscode/1.104.1";

export class CopilotAdapter implements AIProviderAdapter {
  readonly type = "copilot";

  private getHeaders(config: AIProviderConfig): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.apiKey}`,
      "Editor-Version": COPILOT_EDITOR_VERSION,
      "Copilot-Integration-Id": "vscode-chat",
    };
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
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
      stream: false,
    };

    const response = await fetch(`${COPILOT_BASE_URL}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[copilot] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const choice = data.choices?.[0];
    const text = choice?.message?.content || "";

    const usage = data.usage || {};

    return {
      text,
      inputTokens: usage.prompt_tokens || 0,
      outputTokens: usage.completion_tokens || 0,
      modelUsed: data.model || options.model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const headers = this.getHeaders(config);
    delete headers["Content-Type"];

    try {
      const response = await fetch(`${COPILOT_BASE_URL}/models`, { headers });
      if (!response.ok) return getStaticCopilotModels();

      const data = await response.json();
      const models = data.data || [];
      return models.map((m: { id: string; name?: string }) => ({
        modelId: m.id,
        displayName: m.name || m.id,
        description: "via GitHub Copilot",
        inputTokenLimit: 128000,
        outputTokenLimit: 8192,
      }));
    } catch {
      return getStaticCopilotModels();
    }
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const headers = this.getHeaders(config);
    delete headers["Content-Type"];

    try {
      const response = await fetch(`${COPILOT_BASE_URL}/models`, { headers });
      if (response.ok) return { ok: true };
      if (response.status === 401) return { ok: false, error: "Token expirado o inválido" };
      return { ok: false, error: `HTTP ${response.status}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

function getStaticCopilotModels(): AIAvailableModel[] {
  return [
    { modelId: "gpt-4o", displayName: "GPT-4o (Copilot)", inputTokenLimit: 128000, outputTokenLimit: 16384 },
    { modelId: "gpt-4o-mini", displayName: "GPT-4o Mini (Copilot)", inputTokenLimit: 128000, outputTokenLimit: 16384 },
    { modelId: "claude-3.5-sonnet", displayName: "Claude 3.5 Sonnet (Copilot)", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "gemini-2.0-flash", displayName: "Gemini 2.0 Flash (Copilot)", inputTokenLimit: 1000000, outputTokenLimit: 8192 },
  ];
}

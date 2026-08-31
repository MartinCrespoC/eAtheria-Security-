import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

const GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta";

export class GoogleOAuthAdapter implements AIProviderAdapter {
  readonly type = "google-gemini-oauth";

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    // apiKey here is the OAuth access token
    const accessToken = config.apiKey;

    const body: Record<string, unknown> = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: options.temperature ?? 0.7,
        maxOutputTokens: options.maxOutputTokens ?? 8192,
      },
    };

    if (options.systemInstruction) {
      body.systemInstruction = { parts: [{ text: options.systemInstruction }] };
    }

    const url = `${GEMINI_API_URL}/models/${options.model}:generateContent`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[google-oauth] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const candidate = data.candidates?.[0];
    const text = candidate?.content?.parts?.map((p: { text?: string }) => p.text || "").join("") || "";

    const usage = data.usageMetadata || {};

    return {
      text,
      inputTokens: usage.promptTokenCount || 0,
      outputTokens: usage.candidatesTokenCount || 0,
      modelUsed: options.model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const accessToken = config.apiKey;

    try {
      const response = await fetch(`${GEMINI_API_URL}/models?pageSize=100`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) return [];

      const data = await response.json();
      const models = (data.models || []) as Array<{
        name: string;
        displayName?: string;
        description?: string;
        inputTokenLimit?: number;
        outputTokenLimit?: number;
        supportedGenerationMethods?: string[];
      }>;

      return models
        .filter((m) => m.supportedGenerationMethods?.includes("generateContent"))
        .map((m) => ({
          modelId: m.name.replace("models/", ""),
          displayName: m.displayName || m.name.replace("models/", ""),
          description: m.description || "",
          inputTokenLimit: m.inputTokenLimit || 0,
          outputTokenLimit: m.outputTokenLimit || 0,
        }));
    } catch {
      return [];
    }
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const accessToken = config.apiKey;

    try {
      const response = await fetch(`${GEMINI_API_URL}/models?pageSize=1`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (response.ok) return { ok: true };
      if (response.status === 401) return { ok: false, error: "Token OAuth expirado — reconectar" };
      return { ok: false, error: `HTTP ${response.status}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

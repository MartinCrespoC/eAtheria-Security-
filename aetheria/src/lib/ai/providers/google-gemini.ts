import { GoogleGenerativeAI } from "@google/generative-ai";
import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

export class GoogleGeminiAdapter implements AIProviderAdapter {
  readonly type = "google-gemini";

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const genAI = new GoogleGenerativeAI(config.apiKey);

    const model = genAI.getGenerativeModel({
      model: options.model,
      systemInstruction: options.systemInstruction,
      generationConfig: {
        temperature: options.temperature ?? 0.7,
        maxOutputTokens: options.maxOutputTokens ?? 8192,
      },
    });

    const result = await model.generateContent(prompt);
    const response = result.response;
    const text = response.text();

    const usage = response.usageMetadata;
    const inputTokens = usage?.promptTokenCount || 0;
    const outputTokens = usage?.candidatesTokenCount || 0;

    return {
      text,
      inputTokens,
      outputTokens,
      modelUsed: options.model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${config.apiKey}&pageSize=100`
      );
      if (!res.ok) return [];

      const data = await res.json();
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
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${config.apiKey}&pageSize=1`
      );
      if (res.ok) return { ok: true };
      const errText = await res.text();
      return { ok: false, error: `HTTP ${res.status}: ${errText.substring(0, 200)}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

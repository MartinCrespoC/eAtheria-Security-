import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

const API_VERSION = "2024-06-01";

export class AzureOpenAIAdapter implements AIProviderAdapter {
  readonly type = "azure-openai";

  private getEndpoint(config: AIProviderConfig): string {
    // baseUrl should be like: https://{resource-name}.openai.azure.com
    if (!config.baseUrl) {
      throw new Error("[azure-openai] baseUrl is required (e.g. https://my-resource.openai.azure.com)");
    }
    return config.baseUrl.replace(/\/+$/, "");
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const endpoint = this.getEndpoint(config);
    const deploymentId = options.model; // In Azure, model = deployment name
    const apiVersion = (config.config?.apiVersion as string) || API_VERSION;

    const messages: Array<{ role: string; content: string }> = [];
    if (options.systemInstruction) {
      messages.push({ role: "system", content: options.systemInstruction });
    }
    messages.push({ role: "user", content: prompt });

    const body: Record<string, unknown> = {
      messages,
      temperature: options.temperature ?? 0.7,
      max_tokens: options.maxOutputTokens ?? 8192,
    };

    const url = `${endpoint}/openai/deployments/${deploymentId}/chat/completions?api-version=${apiVersion}`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": config.apiKey,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[azure-openai] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const choice = data.choices?.[0];
    const text = choice?.message?.content || "";

    const usage = data.usage || {};

    return {
      text,
      inputTokens: usage.prompt_tokens || 0,
      outputTokens: usage.completion_tokens || 0,
      modelUsed: data.model || deploymentId,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const endpoint = this.getEndpoint(config);
    const apiVersion = (config.config?.apiVersion as string) || API_VERSION;

    try {
      const response = await fetch(
        `${endpoint}/openai/deployments?api-version=${apiVersion}`,
        {
          headers: { "api-key": config.apiKey },
        }
      );

      if (!response.ok) return [];

      const data = await response.json();
      const deployments = data.data || [];

      return deployments.map((d: { id: string; model: string; status: string }) => ({
        modelId: d.id,
        displayName: `${d.id} (${d.model})`,
        description: `Status: ${d.status}`,
        inputTokenLimit: 0,
        outputTokenLimit: 0,
      }));
    } catch {
      return [];
    }
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const endpoint = this.getEndpoint(config);
    const apiVersion = (config.config?.apiVersion as string) || API_VERSION;

    try {
      const response = await fetch(
        `${endpoint}/openai/deployments?api-version=${apiVersion}`,
        {
          headers: { "api-key": config.apiKey },
        }
      );

      if (response.ok) return { ok: true };
      if (response.status === 401) return { ok: false, error: "API key inválida" };
      return { ok: false, error: `HTTP ${response.status}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Connection failed" };
    }
  }
}

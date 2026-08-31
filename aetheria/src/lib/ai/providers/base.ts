export interface AIGenerateOptions {
  model: string;
  temperature?: number;
  maxOutputTokens?: number;
  systemInstruction?: string;
}

export interface AIGenerateResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
  modelUsed: string;
}

export interface AIProviderConfig {
  apiKey: string;
  baseUrl?: string;
  config?: Record<string, unknown>;
  serviceAccountJson?: string; // Vertex AI: Google Cloud service account JSON
  binaryPath?: string;         // CLI providers: path to the binary
}

export interface AIProviderAdapter {
  readonly type: string;

  generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse>;

  listModels(config: AIProviderConfig): Promise<AIAvailableModel[]>;

  testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }>;
}

export interface AIAvailableModel {
  modelId: string;
  displayName: string;
  description?: string;
  inputTokenLimit?: number;
  outputTokenLimit?: number;
}

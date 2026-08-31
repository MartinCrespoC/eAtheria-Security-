import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

/**
 * Google Vertex AI Adapter
 * Uses the Vertex AI REST API with service account authentication.
 * Endpoint: https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/google/models/{model}:generateContent
 */
export class VertexAIAdapter implements AIProviderAdapter {
  readonly type = "google-vertex";

  private parseServiceAccount(config: AIProviderConfig): {
    projectId: string;
    region: string;
    clientEmail: string;
    privateKey: string;
  } {
    const saJson = config.serviceAccountJson;
    if (!saJson) {
      throw new Error("Vertex AI requiere un service account JSON configurado");
    }

    const sa = JSON.parse(saJson);
    const region = (config.config?.region as string) || "us-central1";

    return {
      projectId: sa.project_id,
      region,
      clientEmail: sa.client_email,
      privateKey: sa.private_key,
    };
  }

  private async getAccessToken(clientEmail: string, privateKey: string): Promise<string> {
    // Create a JWT for OAuth2 token exchange
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        iss: clientEmail,
        scope: "https://www.googleapis.com/auth/cloud-platform",
        aud: "https://oauth2.googleapis.com/token",
        iat: now,
        exp: now + 3600,
      })
    ).toString("base64url");

    // Sign with RSA-SHA256
    const { createSign } = await import("crypto");
    const sign = createSign("RSA-SHA256");
    sign.update(`${header}.${payload}`);
    const signature = sign.sign(privateKey, "base64url");

    const jwt = `${header}.${payload}.${signature}`;

    // Exchange JWT for access token
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Vertex AI OAuth2 token error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    return data.access_token;
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const { projectId, region, clientEmail, privateKey } = this.parseServiceAccount(config);
    const accessToken = await this.getAccessToken(clientEmail, privateKey);

    const model = options.model || "gemini-2.5-flash";
    const url = `https://${region}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${region}/publishers/google/models/${model}:generateContent`;

    const body: Record<string, unknown> = {
      contents: [
        {
          role: "user",
          parts: [{ text: prompt }],
        },
      ],
      generationConfig: {
        temperature: options.temperature ?? 0.7,
        maxOutputTokens: options.maxOutputTokens ?? 8192,
      },
    };

    if (options.systemInstruction) {
      body.systemInstruction = {
        parts: [{ text: options.systemInstruction }],
      };
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Vertex AI API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const inputTokens = data.usageMetadata?.promptTokenCount || 0;
    const outputTokens = data.usageMetadata?.candidatesTokenCount || 0;

    return {
      text,
      inputTokens,
      outputTokens,
      modelUsed: model,
    };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    // Vertex AI models are the same as Gemini models but accessed via enterprise endpoint
    return [
      { modelId: "gemini-2.5-flash", displayName: "Gemini 2.5 Flash (Vertex)" },
      { modelId: "gemini-2.5-pro", displayName: "Gemini 2.5 Pro (Vertex)" },
      { modelId: "gemini-2.5-flash-lite", displayName: "Gemini 2.5 Flash-Lite (Vertex)" },
      { modelId: "gemini-2.0-flash", displayName: "Gemini 2.0 Flash (Vertex)" },
    ];
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      const { clientEmail, privateKey } = this.parseServiceAccount(config);
      const token = await this.getAccessToken(clientEmail, privateKey);
      return { ok: !!token };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : "Error de conexión con Vertex AI",
      };
    }
  }
}

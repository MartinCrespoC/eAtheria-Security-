import crypto from "crypto";
import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

export class AWSBedrockAdapter implements AIProviderAdapter {
  readonly type = "aws-bedrock";

  private getRegion(config: AIProviderConfig): string {
    return (config.config?.region as string) || "us-east-1";
  }

  private getCredentials(config: AIProviderConfig): { accessKeyId: string; secretAccessKey: string; sessionToken?: string } {
    // apiKey format: "ACCESS_KEY_ID:SECRET_ACCESS_KEY" or "ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN"
    const parts = config.apiKey.split(":");
    if (parts.length < 2) {
      throw new Error("[aws-bedrock] API key must be in format ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]");
    }
    return {
      accessKeyId: parts[0],
      secretAccessKey: parts[1],
      sessionToken: parts[2] || undefined,
    };
  }

  private sign(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: string,
    credentials: { accessKeyId: string; secretAccessKey: string; sessionToken?: string },
    region: string,
    service: string
  ): Record<string, string> {
    const now = new Date();
    const dateStamp = now.toISOString().replace(/[:-]|\.\d{3}/g, "").substring(0, 8);
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");

    const signedHeaders: Record<string, string> = { ...headers };
    signedHeaders["x-amz-date"] = amzDate;
    if (credentials.sessionToken) {
      signedHeaders["x-amz-security-token"] = credentials.sessionToken;
    }

    const parsedUrl = new URL(url);
    const canonicalUri = parsedUrl.pathname;
    const canonicalQuerystring = parsedUrl.search.substring(1);

    const headerKeys = Object.keys(signedHeaders).sort();
    const canonicalHeaders = headerKeys.map((k) => `${k.toLowerCase()}:${signedHeaders[k].trim()}\n`).join("");
    const signedHeadersList = headerKeys.map((k) => k.toLowerCase()).join(";");

    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");

    const canonicalRequest = [
      method, canonicalUri, canonicalQuerystring,
      canonicalHeaders, signedHeadersList, payloadHash,
    ].join("\n");

    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256", amzDate, credentialScope,
      crypto.createHash("sha256").update(canonicalRequest).digest("hex"),
    ].join("\n");

    const signingKey = getSignatureKey(credentials.secretAccessKey, dateStamp, region, service);
    const signature = crypto.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

    signedHeaders["Authorization"] =
      `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeadersList}, Signature=${signature}`;

    return signedHeaders;
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const region = this.getRegion(config);
    const credentials = this.getCredentials(config);
    const modelId = options.model;

    const messages: Array<{ role: string; content: Array<{ text: string }> }> = [
      { role: "user", content: [{ text: prompt }] },
    ];

    const body: Record<string, unknown> = {
      messages,
      inferenceConfig: {
        maxTokens: options.maxOutputTokens ?? 8192,
        temperature: options.temperature ?? 0.7,
      },
    };

    if (options.systemInstruction) {
      body.system = [{ text: options.systemInstruction }];
    }

    const url = `https://bedrock-runtime.${region}.amazonaws.com/model/${encodeURIComponent(modelId)}/converse`;
    const bodyStr = JSON.stringify(body);

    const baseHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      host: `bedrock-runtime.${region}.amazonaws.com`,
    };

    const signedHeaders = this.sign("POST", url, baseHeaders, bodyStr, credentials, region, "bedrock");

    const response = await fetch(url, {
      method: "POST",
      headers: signedHeaders,
      body: bodyStr,
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`[aws-bedrock] API error ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const output = data.output?.message?.content || [];
    const text = output.map((b: { text?: string }) => b.text || "").join("");

    const usage = data.usage || {};

    return {
      text,
      inputTokens: usage.inputTokens || 0,
      outputTokens: usage.outputTokens || 0,
      modelUsed: modelId,
    };
  }

  async listModels(_config: AIProviderConfig): Promise<AIAvailableModel[]> {
    // Bedrock requires ListFoundationModels API — return static fallback
    return getStaticBedrockModels();
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      this.getCredentials(config);
      // Basic validation that credentials format is correct
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "Invalid credentials" };
    }
  }
}

function getSignatureKey(key: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = crypto.createHmac("sha256", `AWS4${key}`).update(dateStamp).digest();
  const kRegion = crypto.createHmac("sha256", kDate).update(region).digest();
  const kService = crypto.createHmac("sha256", kRegion).update(service).digest();
  return crypto.createHmac("sha256", kService).update("aws4_request").digest();
}

function getStaticBedrockModels(): AIAvailableModel[] {
  return [
    { modelId: "us.anthropic.claude-sonnet-4-6", displayName: "Claude Sonnet 4.6 (Bedrock)", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "us.anthropic.claude-opus-4-6-v1", displayName: "Claude Opus 4.6 (Bedrock)", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "us.anthropic.claude-haiku-4-5-20251001-v1:0", displayName: "Claude Haiku 4.5 (Bedrock)", inputTokenLimit: 200000, outputTokenLimit: 8192 },
    { modelId: "us.amazon.nova-pro-v1:0", displayName: "Amazon Nova Pro", inputTokenLimit: 300000, outputTokenLimit: 5000 },
    { modelId: "us.amazon.nova-lite-v1:0", displayName: "Amazon Nova Lite", inputTokenLimit: 300000, outputTokenLimit: 5000 },
  ];
}

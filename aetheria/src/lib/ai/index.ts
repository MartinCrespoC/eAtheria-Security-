import { prisma } from "../db";
import { decrypt } from "./encryption";
import { getEnvApiKey } from "./env-keys";
import { getAdapter } from "./registry";
import type { AIProviderConfig } from "./providers/base";

export interface GenerateOptions {
  model?: string;
  provider?: string;
  temperature?: number;
  maxOutputTokens?: number;
  systemInstruction?: string;
  companyId?: string;
}

export interface AIResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
  cost: number;
  modelUsed: string;
  providerUsed: string;
}

export async function generateText(
  prompt: string,
  options: GenerateOptions = {}
): Promise<AIResponse> {
  // 1. Resolve which model to use
  const { modelRecord, providerRecord } = await resolveModel(options.model, options.provider);

  // 2. Get adapter for the provider type
  const adapter = getAdapter(providerRecord.type, providerRecord.slug);

  // 3. Build provider config (decrypt API key)
  const providerConfig = await buildProviderConfig(providerRecord);

  // 4. Execute generation
  const result = await adapter.generate(prompt, {
    model: modelRecord.modelId,
    temperature: options.temperature,
    maxOutputTokens: options.maxOutputTokens,
    systemInstruction: options.systemInstruction,
  }, providerConfig);

  // 5. Calculate cost
  const inputCost = Number(modelRecord.inputTokenCost);
  const outputCost = Number(modelRecord.outputTokenCost);
  const cost =
    (result.inputTokens / 1_000_000) * inputCost +
    (result.outputTokens / 1_000_000) * outputCost;

  // 6. Track usage
  if (options.companyId !== undefined) {
    await trackTokenUsage(
      modelRecord.id,
      result.inputTokens,
      result.outputTokens,
      cost,
      options.companyId
    );
  }

  return {
    text: result.text,
    inputTokens: result.inputTokens,
    outputTokens: result.outputTokens,
    cost,
    modelUsed: result.modelUsed,
    providerUsed: providerRecord.slug,
  };
}

// Backward compatibility alias
export async function generateWithGemini(
  prompt: string,
  options: {
    model?: string;
    temperature?: number;
    maxOutputTokens?: number;
    systemInstruction?: string;
    companyId?: string;
  } = {}
): Promise<{
  text: string;
  inputTokens: number;
  outputTokens: number;
  cost: number;
  modelUsed: string;
}> {
  const result = await generateText(prompt, options);
  return {
    text: result.text,
    inputTokens: result.inputTokens,
    outputTokens: result.outputTokens,
    cost: result.cost,
    modelUsed: result.modelUsed,
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

interface ResolvedModel {
  modelRecord: {
    id: string;
    modelId: string;
    inputTokenCost: unknown;
    outputTokenCost: unknown;
  };
  providerRecord: {
    id: string;
    slug: string;
    type: string;
    baseUrl: string | null;
    apiKeyEnc: string | null;
    authType: string;
    config: unknown;
  };
}

async function resolveModel(modelId?: string, providerSlug?: string): Promise<ResolvedModel> {
  let modelRecord;

  if (modelId) {
    // Find by modelId
    modelRecord = await prisma.aIModel.findFirst({
      where: { modelId, isActive: true },
      include: { aiProvider: true },
    });
  }

  if (!modelRecord) {
    // Fallback to default model
    modelRecord = await prisma.aIModel.findFirst({
      where: { isDefault: true, isActive: true },
      include: { aiProvider: true },
    });
  }

  if (!modelRecord) {
    throw new Error("No active AI model found. Configure at least one model in /admin/ai-models.");
  }

  // Resolve provider
  let providerRecord = modelRecord.aiProvider;

  if (!providerRecord && providerSlug) {
    providerRecord = await prisma.aIProvider.findUnique({
      where: { slug: providerSlug, isActive: true },
    });
  }

  if (!providerRecord) {
    // Legacy fallback: look up by the old `provider` string field
    providerRecord = await prisma.aIProvider.findFirst({
      where: { slug: modelRecord.provider, isActive: true },
    });
  }

  if (!providerRecord) {
    // Ultimate fallback for backward compat: use gemini with env var
    providerRecord = {
      id: "legacy",
      slug: "gemini",
      type: "google-gemini",
      baseUrl: null,
      apiKeyEnc: null,
      authType: "api_key",
      config: null,
    } as unknown as typeof providerRecord;
  }

  return {
    modelRecord: {
      id: modelRecord.id,
      modelId: modelRecord.modelId,
      inputTokenCost: modelRecord.inputTokenCost,
      outputTokenCost: modelRecord.outputTokenCost,
    },
    providerRecord: providerRecord!,
  };
}

async function buildProviderConfig(
  provider: {
    id: string;
    slug: string;
    type: string;
    baseUrl: string | null;
    apiKeyEnc: string | null;
    authType: string;
    config: unknown;
  }
): Promise<AIProviderConfig> {
  let apiKey = "";

  if (provider.authType === "none") {
    // CLI providers (grok-cli, qoder-cli) don't need an API key
    return {
      apiKey: "",
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
      binaryPath: (provider.config as Record<string, unknown>)?.binary as string || undefined,
    };
  }

  if (provider.authType === "service_account") {
    // Vertex AI: apiKeyEnc stores the encrypted service account JSON
    const serviceAccountJson = provider.apiKeyEnc ? decrypt(provider.apiKeyEnc) : "";
    if (!serviceAccountJson) {
      throw new Error(`No service account configured for provider "${provider.slug}". Configure it in /admin/ai-providers.`);
    }
    return {
      apiKey: "",
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
      serviceAccountJson,
    };
  }

  if (provider.apiKeyEnc) {
    // Decrypt stored key
    apiKey = decrypt(provider.apiKeyEnc);
  } else if (provider.authType === "oauth") {
    // OAuth providers store tokens in config JSON
    const cfg = provider.config as Record<string, unknown> | null;
    if (cfg?.accessToken) {
      apiKey = decrypt(cfg.accessToken as string);
    }
  }

  if (!apiKey) {
    // Env fallback: .env keys (OPENAI_API_KEY/OPEN_AI, OPENROUTER_API_KEY/OPEN_ROUTER, ...)
    apiKey = getEnvApiKey(provider.slug);
  }

  if (!apiKey) {
    throw new Error(`No API key configured for provider "${provider.slug}". Configure it in /admin/ai-providers.`);
  }

  return {
    apiKey,
    baseUrl: provider.baseUrl || undefined,
    config: (provider.config as Record<string, unknown>) || undefined,
  };
}

async function trackTokenUsage(
  modelId: string,
  inputTokens: number,
  outputTokens: number,
  cost: number,
  companyId?: string
) {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const existing = await prisma.tokenUsage.findFirst({
      where: {
        date: today,
        modelId,
        companyId: companyId ?? null,
      },
    });

    if (existing) {
      await prisma.tokenUsage.update({
        where: { id: existing.id },
        data: {
          inputTokens: { increment: BigInt(inputTokens) },
          outputTokens: { increment: BigInt(outputTokens) },
          totalCost: { increment: cost },
        },
      });
    } else {
      await prisma.tokenUsage.create({
        data: {
          date: today,
          modelId,
          companyId: companyId ?? null,
          inputTokens: BigInt(inputTokens),
          outputTokens: BigInt(outputTokens),
          totalCost: cost,
        },
      });
    }
  } catch (error) {
    console.error("Error tracking token usage:", error);
  }
}

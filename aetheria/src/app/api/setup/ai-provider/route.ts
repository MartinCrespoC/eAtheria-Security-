import { NextRequest, NextResponse } from "next/server";
import { getPrisma } from "@/lib/infrastructure/db-adapter";
import { encrypt } from "@/lib/ai/encryption";
import { getAdapter } from "@/lib/ai/registry";
import { discoverAndUpsertModels, setDefaultModel } from "@/lib/ai/model-discovery";

export const dynamic = "force-dynamic";

/**
 * Check if setup is already complete.
 */
async function isSetupComplete(): Promise<boolean> {
  try {
    const client = getPrisma();
    const config = await client.systemConfig.findUnique({
      where: { key: "setup_complete" },
    });
    return config?.value === true;
  } catch {
    return false;
  }
}

/**
 * GET /api/setup/ai-provider
 *
 * Lists the API-key based AI providers so the setup wizard can offer a
 * "connect your AI" step. Never returns the stored key — only a boolean.
 */
export async function GET() {
  if (await isSetupComplete()) {
    return NextResponse.json(
      { error: "Setup is already complete" },
      { status: 403 }
    );
  }

  try {
    const client = getPrisma();

    const providers = await client.aIProvider.findMany({
      where: { authType: "api_key", companyId: null },
      select: {
        id: true,
        slug: true,
        name: true,
        type: true,
        baseUrl: true,
        isActive: true,
        apiKeyEnc: true,
      },
      orderBy: { name: "asc" },
    });

    // Count active models per provider so the UI can tell which providers
    // are ready to drive analyses out of the box.
    const models = await client.aIModel.findMany({
      where: { isActive: true },
      select: { providerId: true },
    });
    const modelCount = new Map<string, number>();
    for (const m of models) {
      if (m.providerId) {
        modelCount.set(m.providerId, (modelCount.get(m.providerId) || 0) + 1);
      }
    }

    const list = providers.map((p) => ({
      id: p.id,
      slug: p.slug,
      name: p.name,
      type: p.type,
      baseUrl: p.baseUrl,
      isActive: p.isActive,
      hasApiKey: !!p.apiKeyEnc,
      configured: !!p.apiKeyEnc && p.isActive,
      modelCount: modelCount.get(p.id) || 0,
    }));

    return NextResponse.json({ providers: list });
  } catch (error) {
    console.error("[SETUP] AI provider list error:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}

/**
 * POST /api/setup/ai-provider
 *
 * Body: { providerId, apiKey, baseUrl?, testOnly?, defaultModelId? }
 *
 * - testOnly=true  → validates the key against the provider without saving it.
 * - otherwise      → encrypts & stores the key, activates the provider and
 *                    promotes one of its models to "default" so analyses work
 *                    immediately after setup.
 */
export async function POST(request: NextRequest) {
  if (await isSetupComplete()) {
    return NextResponse.json(
      { error: "Setup is already complete" },
      { status: 403 }
    );
  }

  try {
    const body = await request.json();
    const { providerId, apiKey, baseUrl, testOnly, defaultModelId } = body as {
      providerId?: string;
      apiKey?: string;
      baseUrl?: string;
      testOnly?: boolean;
      defaultModelId?: string;
    };

    if (!providerId) {
      return NextResponse.json(
        { ok: false, error: "providerId is required" },
        { status: 400 }
      );
    }
    if (!apiKey || typeof apiKey !== "string" || apiKey.trim().length < 8) {
      return NextResponse.json(
        { ok: false, error: "A valid API key is required" },
        { status: 400 }
      );
    }

    const client = getPrisma();
    const provider = await client.aIProvider.findUnique({
      where: { id: providerId },
    });
    if (!provider) {
      return NextResponse.json(
        { ok: false, error: "Provider not found" },
        { status: 404 }
      );
    }

    const key = apiKey.trim();
    const effectiveBaseUrl =
      baseUrl && baseUrl.trim() ? baseUrl.trim() : provider.baseUrl || undefined;
    const providerConfig =
      (provider.config as Record<string, unknown> | null) || undefined;

    const adapter = getAdapter(provider.type, provider.slug);

    // Test-only: validate the key without persisting anything.
    if (testOnly) {
      try {
        const result = await adapter.testConnection({
          apiKey: key,
          baseUrl: effectiveBaseUrl,
          config: providerConfig,
        });
        return NextResponse.json(result);
      } catch (error) {
        return NextResponse.json({
          ok: false,
          error:
            error instanceof Error ? error.message : "Connection test failed",
        });
      }
    }

    // Save: encrypt the key, activate the provider.
    await client.aIProvider.update({
      where: { id: provider.id },
      data: {
        apiKeyEnc: encrypt(key),
        baseUrl: effectiveBaseUrl ?? provider.baseUrl,
        isActive: true,
      },
    });

    // Discover the provider's real model catalog (adapter.listModels) and
    // upsert it, so the wizard can offer the models that actually work
    // with this key. Falls back to seeded models if discovery fails.
    const discovery = await discoverAndUpsertModels(
      { ...provider, baseUrl: effectiveBaseUrl ?? provider.baseUrl },
      key
    );

    // Promote a model to default so the analysis pipeline resolves it (and
    // its freshly-stored key) right away: the explicitly chosen one, else
    // the first discovered/seeded model of this provider.
    let defaultModelRecord = defaultModelId
      ? await client.aIModel.findFirst({
          where: { id: defaultModelId, providerId: provider.id },
        })
      : null;
    if (!defaultModelRecord) {
      defaultModelRecord = await client.aIModel.findFirst({
        where: { providerId: provider.id, isActive: true },
        orderBy: { isDefault: "desc" },
      });
    }
    if (defaultModelRecord) {
      await setDefaultModel(defaultModelRecord.id, provider.id);
    }

    // Best-effort confirmation test with the saved key.
    let test: { ok: boolean; error?: string } = { ok: true };
    try {
      test = await adapter.testConnection({
        apiKey: key,
        baseUrl: effectiveBaseUrl,
        config: providerConfig,
      });
    } catch (error) {
      test = {
        ok: false,
        error: error instanceof Error ? error.message : "Connection test failed",
      };
    }

    return NextResponse.json({
      success: true,
      configured: true,
      defaultModel: defaultModelRecord?.name || null,
      models: discovery.models,
      discoveryError: discovery.error,
      test,
    });
  } catch (error) {
    console.error("[SETUP] AI provider save error:", error);
    return NextResponse.json(
      { ok: false, error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}

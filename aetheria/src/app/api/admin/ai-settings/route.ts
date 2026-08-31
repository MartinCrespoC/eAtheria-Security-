import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { encrypt } from "@/lib/ai/encryption";
import { getAdapter } from "@/lib/ai/registry";
import { discoverAndUpsertModels, setDefaultModel } from "@/lib/ai/model-discovery";

/** Provider templates the admin can instantiate with their own key. */
const PROVIDER_TEMPLATES: Record<string, { name: string; type: string; baseUrl: string | null }> = {
  openrouter: { name: "OpenRouter", type: "openai-compatible", baseUrl: "https://openrouter.ai/api/v1" },
  openai: { name: "OpenAI", type: "openai-compatible", baseUrl: "https://api.openai.com/v1" },
  anthropic: { name: "Anthropic", type: "anthropic", baseUrl: null },
  gemini: { name: "Google Gemini", type: "google-gemini", baseUrl: null },
  deepseek: { name: "DeepSeek", type: "openai-compatible", baseUrl: "https://api.deepseek.com" },
  custom: { name: "Custom (OpenAI-compatible)", type: "openai-compatible", baseUrl: null },
};

/** Individual mode: the single internal workspace, resolved automatically. */
async function getWorkspace() {
  return prisma.company.findFirst({
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      name: true,
      aiProviderId: true,
      aiTokenLimit: true,
      aiCostLimit: true,
      settings: true,
      aiProvider: {
        select: {
          id: true,
          name: true,
          slug: true,
          type: true,
          companyId: true,
          baseUrl: true,
          apiKeyEnc: true,
        },
      },
    },
  });
}

/**
 * GET /api/admin/ai-settings
 * Returns the workspace AI settings: assigned provider, available models,
 * and model preferences stored in the workspace settings.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const company = await getWorkspace();
    if (!company) {
      return NextResponse.json({ error: "Workspace no encontrado" }, { status: 404 });
    }

    // If the workspace has no assigned provider, fall back to a global provider
    let aiProvider = company.aiProvider;
    let usingSystemDefault = false;
    if (!aiProvider) {
      const defaultProvider = await prisma.aIProvider.findFirst({
        where: { isActive: true, companyId: null },
        select: { id: true, name: true, slug: true, type: true, baseUrl: true, apiKeyEnc: true, companyId: true },
        orderBy: { createdAt: "asc" },
      });
      if (defaultProvider) {
        aiProvider = defaultProvider;
        usingSystemDefault = true;
      }
    }

    const providerFilter = aiProvider
      ? { providerId: aiProvider.id, isActive: true }
      : { isActive: true };

    const models = await prisma.aIModel.findMany({
      where: providerFilter,
      select: {
        id: true,
        name: true,
        modelId: true,
        provider: true,
        inputTokenCost: true,
        outputTokenCost: true,
        maxInputTokens: true,
        maxOutputTokens: true,
        isActive: true,
        isDefault: true,
        aiProvider: { select: { id: true, name: true, slug: true } },
      },
      orderBy: { name: "asc" },
    });

    const settings = (company.settings as Record<string, unknown>) || {};
    const modelPreferences = (settings.modelPreferences as Record<string, string>) || {};

    return NextResponse.json({
      company: {
        id: company.id,
        name: company.name,
        aiProvider: aiProvider
          ? {
              id: aiProvider.id,
              name: aiProvider.name,
              slug: aiProvider.slug,
              type: aiProvider.type,
              baseUrl: "baseUrl" in aiProvider ? aiProvider.baseUrl : null,
              hasApiKey:
                "apiKeyEnc" in aiProvider ? !!aiProvider.apiKeyEnc : false,
              isOwn:
                "companyId" in aiProvider &&
                aiProvider.companyId === company.id,
            }
          : null,
        usingSystemDefault,
        aiTokenLimit: company.aiTokenLimit,
        aiCostLimit: company.aiCostLimit,
      },
      models,
      modelPreferences,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching AI settings:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PUT /api/admin/ai-settings
 * Update model preferences or manage the workspace's own AI provider.
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await requireSystemAdmin();

    const body = await request.json();
    const { modelPreferences, provider: providerPayload, defaultModelId } = body;

    const workspace = await getWorkspace();
    if (!workspace) {
      return NextResponse.json({ error: "Workspace no encontrado" }, { status: 404 });
    }
    const companyId = workspace.id;

    // ── Own-provider management ──────────────────────────────────────────
    if (providerPayload) {
      const { templateSlug, apiKey, baseUrl, testOnly } = providerPayload as {
        templateSlug?: string;
        apiKey?: string;
        baseUrl?: string;
        testOnly?: boolean;
      };

      const template = templateSlug ? PROVIDER_TEMPLATES[templateSlug] : undefined;
      if (!template) {
        return NextResponse.json({ error: "Proveedor no soportado" }, { status: 400 });
      }
      if (!apiKey || apiKey.trim().length < 8) {
        return NextResponse.json({ error: "API key inválida" }, { status: 400 });
      }
      if (templateSlug === "custom" && !baseUrl?.trim()) {
        return NextResponse.json({ error: "Base URL requerida para proveedor custom" }, { status: 400 });
      }

      const key = apiKey.trim();
      const effectiveBaseUrl = baseUrl?.trim() || template.baseUrl || undefined;
      const adapter = getAdapter(template.type, templateSlug!);

      if (testOnly) {
        const result = await adapter.testConnection({ apiKey: key, baseUrl: effectiveBaseUrl });
        return NextResponse.json(result);
      }

      // One owned provider per workspace: update it if the template changed,
      // otherwise create it. Slug must stay globally unique.
      let owned = await prisma.aIProvider.findFirst({ where: { companyId } });

      const data = {
        name: template.name,
        type: template.type,
        baseUrl: effectiveBaseUrl ?? null,
        apiKeyEnc: encrypt(key),
        authType: "api_key",
        isActive: true,
      };

      if (owned) {
        owned = await prisma.aIProvider.update({ where: { id: owned.id }, data });
      } else {
        owned = await prisma.aIProvider.create({
          data: { ...data, slug: `${templateSlug}-${companyId.slice(-8)}`, companyId },
        });
      }

      // Assign it to the workspace so the selector picks it first
      await prisma.company.update({
        where: { id: companyId },
        data: { aiProviderId: owned.id },
      });

      // Discover the models this key can actually use
      const discovery = await discoverAndUpsertModels(owned, key);

      if (defaultModelId) {
        await setDefaultModel(defaultModelId, owned.id);
      }

      await prisma.auditLog.create({
        data: {
          action: "admin.config.change",
          entityType: "AIProvider",
          entityId: owned.id,
          userId: session.user.id,
          companyId,
          newValues: { templateSlug, baseUrl: effectiveBaseUrl, modelsDiscovered: discovery.models.length } as never,
        },
      });

      const test = await adapter.testConnection({ apiKey: key, baseUrl: effectiveBaseUrl }).catch(() => ({ ok: false as const, error: "test failed" }));

      return NextResponse.json({
        ok: true,
        provider: { id: owned.id, name: owned.name, slug: owned.slug, type: owned.type, baseUrl: owned.baseUrl },
        models: discovery.models,
        discoveryError: discovery.error,
        test,
      });
    }

    if (!modelPreferences || typeof modelPreferences !== "object") {
      // Allow a bare default-model change (scoped to the workspace's provider)
      if (defaultModelId && typeof defaultModelId === "string") {
        const model = await prisma.aIModel.findFirst({
          where: { id: defaultModelId, providerId: workspace.aiProviderId || "__none__" },
        });
        if (!model) {
          return NextResponse.json({ error: "Modelo no pertenece al proveedor" }, { status: 400 });
        }
        await setDefaultModel(model.id, workspace.aiProviderId!);
        return NextResponse.json({ ok: true, defaultModel: model.name });
      }
      return NextResponse.json({ error: "modelPreferences es requerido" }, { status: 400 });
    }

    // Get current settings and merge
    const currentSettings = (workspace.settings as Record<string, unknown>) || {};
    const updatedSettings = {
      ...currentSettings,
      modelPreferences,
    };

    await prisma.company.update({
      where: { id: companyId },
      data: { settings: updatedSettings },
    });

    await prisma.auditLog.create({
      data: {
        action: "admin.config.change",
        entityType: "Company",
        entityId: companyId,
        userId: session.user.id,
        companyId,
        newValues: { modelPreferences } as never,
      },
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating AI settings:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

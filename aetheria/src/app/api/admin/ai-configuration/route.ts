import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { getProviderStatus } from "@/lib/ai/health-monitor";
import { getEnvApiKey } from "@/lib/ai/env-keys";

/**
 * GET /api/admin/ai-configuration
 * Returns the full AI configuration: providers, models, limits, companies.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const [providers, models, companies] = await Promise.all([
      prisma.aIProvider.findMany({
        orderBy: [{ isActive: "desc" }, { name: "asc" }],
        include: {
          _count: { select: { models: true, companies: true } },
        },
      }),
      prisma.aIModel.findMany({
        orderBy: [{ isDefault: "desc" }, { name: "asc" }],
        include: { aiProvider: { select: { id: true, name: true, slug: true } } },
      }),
      prisma.company.findMany({
        select: {
          id: true,
          name: true,
          slug: true,
          aiProviderId: true,
          aiTokenLimit: true,
          aiCostLimit: true,
          aiProvider: { select: { id: true, name: true, slug: true } },
        },
        orderBy: { name: "asc" },
      }),
    ]);

    // Fetch health status for all providers
    const healthPromises = providers.map((p) => getProviderStatus(p.id));
    const healthStatuses = await Promise.all(healthPromises);

    const sanitized = providers.map((p, idx) => {
      const health = healthStatuses[idx];
      return {
        ...p,
        apiKeyEnc: undefined,
        hasApiKey: !!p.apiKeyEnc || !!getEnvApiKey(p.slug),
        keySource: p.apiKeyEnc ? "db" : getEnvApiKey(p.slug) ? "env" : null,
        config: p.authType === "oauth"
          ? { authType: "oauth", hasToken: !!(p.config as Record<string, unknown>)?.accessToken }
          : p.config,
        health: {
          status: health.status,
          latencyMs: health.latencyMs,
          error: health.error,
          lastCheckedAt: health.lastCheckedAt,
        },
      };
    });

    return NextResponse.json({
      providers: sanitized,
      models,
      companies,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching AI configuration:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PATCH /api/admin/ai-configuration
 * Update provider-level fields (fallback, limits, active state).
 */
export async function PATCH(request: NextRequest) {
  try {
    const session = await requireSystemAdmin();
    const body = await request.json();
    const { providerId, fallbackProviderId, maxTokensPerMonth, costLimitPerMonth, isActive, modelDefaults } = body;

    if (!providerId) {
      return NextResponse.json({ error: "providerId es requerido" }, { status: 400 });
    }

    const updateData: Record<string, unknown> = {};

    if (fallbackProviderId !== undefined) {
      // Validate fallback exists and isn't the same provider
      if (fallbackProviderId === providerId) {
        return NextResponse.json({ error: "El fallback no puede ser el mismo provider" }, { status: 400 });
      }
      if (fallbackProviderId) {
        const fallback = await prisma.aIProvider.findUnique({ where: { id: fallbackProviderId } });
        if (!fallback) {
          return NextResponse.json({ error: "Fallback provider no encontrado" }, { status: 404 });
        }
      }
      updateData.fallbackProviderId = fallbackProviderId || null;
    }

    if (maxTokensPerMonth !== undefined) {
      updateData.maxTokensPerMonth = maxTokensPerMonth ?? null;
    }

    if (costLimitPerMonth !== undefined) {
      updateData.costLimitPerMonth = costLimitPerMonth ?? null;
    }

    if (isActive !== undefined) {
      updateData.isActive = isActive;
    }

    if (Object.keys(updateData).length > 0) {
      await prisma.aIProvider.update({
        where: { id: providerId },
        data: updateData,
      });
    }

    // Handle model default assignments per task type
    if (modelDefaults && typeof modelDefaults === "object") {
      // modelDefaults: { sast: modelId, sca: modelId, ... }
      // Store in provider config
      const provider = await prisma.aIProvider.findUnique({ where: { id: providerId } });
      const existingConfig = (provider?.config as Record<string, unknown>) || {};
      await prisma.aIProvider.update({
        where: { id: providerId },
        data: {
          config: { ...existingConfig, taskModelDefaults: modelDefaults },
        },
      });
    }

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "admin.config.change",
        entityType: "AIProvider",
        entityId: providerId,
        userId: session.user.id,
        newValues: { ...updateData, modelDefaults } as never,
      },
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating AI configuration:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

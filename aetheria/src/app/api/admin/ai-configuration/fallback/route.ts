import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/admin/ai-configuration/fallback
 * Returns the fallback configuration for all providers.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const providers = await prisma.aIProvider.findMany({
      orderBy: [{ isActive: "desc" }, { name: "asc" }],
      select: {
        id: true,
        name: true,
        slug: true,
        isActive: true,
        fallbackProviderId: true,
      },
    });

    // Resolve fallback provider names
    const fallbackIds = providers
      .map((p) => p.fallbackProviderId)
      .filter((id): id is string => id !== null);

    const fallbackProviders = await prisma.aIProvider.findMany({
      where: { id: { in: fallbackIds } },
      select: { id: true, name: true, slug: true },
    });

    const fallbackMap = new Map(fallbackProviders.map((p) => [p.id, p]));

    const result = providers.map((p) => ({
      ...p,
      fallbackProvider: p.fallbackProviderId
        ? fallbackMap.get(p.fallbackProviderId) || null
        : null,
    }));

    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching fallback config:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PUT /api/admin/ai-configuration/fallback
 * Update fallback configuration for a provider.
 * Body: { providerId, fallbackProviderId }
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await requireSystemAdmin();
    const body = await request.json();
    const { providerId, fallbackProviderId } = body;

    if (!providerId) {
      return NextResponse.json({ error: "providerId es requerido" }, { status: 400 });
    }

    if (fallbackProviderId === providerId) {
      return NextResponse.json({ error: "El fallback no puede ser el mismo provider" }, { status: 400 });
    }

    if (fallbackProviderId) {
      const fallback = await prisma.aIProvider.findUnique({ where: { id: fallbackProviderId } });
      if (!fallback) {
        return NextResponse.json({ error: "Fallback provider no encontrado" }, { status: 404 });
      }
    }

    await prisma.aIProvider.update({
      where: { id: providerId },
      data: { fallbackProviderId: fallbackProviderId || null },
    });

    await prisma.auditLog.create({
      data: {
        action: "admin.config.change",
        entityType: "AIProvider",
        entityId: providerId,
        userId: session.user.id,
        newValues: { fallbackProviderId } as never,
      },
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating fallback config:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

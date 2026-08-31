import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/admin/ai-configuration/limits
 * Returns global provider limits and per-company limits.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const [providers, companies] = await Promise.all([
      prisma.aIProvider.findMany({
        orderBy: [{ isActive: "desc" }, { name: "asc" }],
        select: {
          id: true,
          name: true,
          slug: true,
          isActive: true,
          maxTokensPerMonth: true,
          costLimitPerMonth: true,
        },
      }),
      prisma.company.findMany({
        select: {
          id: true,
          name: true,
          slug: true,
          aiTokenLimit: true,
          aiCostLimit: true,
          aiProvider: { select: { id: true, name: true } },
        },
        orderBy: { name: "asc" },
      }),
    ]);

    return NextResponse.json({ providers, companies });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching limits:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PUT /api/admin/ai-configuration/limits
 * Update limits for a provider or a company.
 * Body: { type: "provider" | "company", id, maxTokensPerMonth?, costLimit? }
 */
export async function PUT(request: NextRequest) {
  try {
    const session = await requireSystemAdmin();
    const body = await request.json();
    const { type, id, maxTokensPerMonth, costLimit } = body;

    if (!id || !type) {
      return NextResponse.json({ error: "type e id son requeridos" }, { status: 400 });
    }

    let auditNewValues: Record<string, unknown> = {};

    if (type === "provider") {
      const updateData: Record<string, unknown> = {};
      if (maxTokensPerMonth !== undefined) {
        updateData.maxTokensPerMonth = maxTokensPerMonth ?? null;
      }
      if (costLimit !== undefined) {
        updateData.costLimitPerMonth = costLimit ?? null;
      }

      await prisma.aIProvider.update({ where: { id }, data: updateData });
      auditNewValues = {
        entityType: "AIProvider",
        ...updateData,
      };

      await prisma.auditLog.create({
        data: {
          action: "admin.config.change",
          entityType: "AIProvider",
          entityId: id,
          userId: session.user.id,
          newValues: auditNewValues as never,
        },
      });
    } else if (type === "company") {
      const updateData: Record<string, unknown> = {};
      if (maxTokensPerMonth !== undefined) {
        updateData.aiTokenLimit = maxTokensPerMonth ?? null;
      }
      if (costLimit !== undefined) {
        updateData.aiCostLimit = costLimit ?? null;
      }

      await prisma.company.update({ where: { id }, data: updateData });
      auditNewValues = {
        entityType: "Company",
        ...updateData,
      };

      await prisma.auditLog.create({
        data: {
          action: "admin.config.change",
          entityType: "Company",
          entityId: id,
          userId: session.user.id,
          newValues: auditNewValues as never,
        },
      });
    } else {
      return NextResponse.json({ error: "Tipo inválido. Use 'provider' o 'company'" }, { status: 400 });
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating limits:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

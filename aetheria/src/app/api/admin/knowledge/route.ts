/**
 * Admin Knowledge Management API
 * GET /api/admin/knowledge - List skills (paginated, filterable)
 * PATCH /api/admin/knowledge - Toggle isActive, edit CWE mappings
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function GET(req: NextRequest) {
  try {
    await requireSystemAdmin();

    const { searchParams } = new URL(req.url);
    const search = searchParams.get("search") || "";
    const category = searchParams.get("category") || "";
    const isActive = searchParams.get("isActive");
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const pageSize = Math.min(100, Math.max(10, parseInt(searchParams.get("pageSize") || "50", 10)));

    const where: Record<string, unknown> = {};
    if (search) {
      where.OR = [
        { name: { contains: search, mode: "insensitive" } },
        { slug: { contains: search, mode: "insensitive" } },
        { description: { contains: search, mode: "insensitive" } },
      ];
    }
    if (category) {
      where.category = category;
    }
    if (isActive !== null && isActive !== undefined && isActive !== "") {
      where.isActive = isActive === "true";
    }

    const [skills, total, categories, stats] = await Promise.all([
      prisma.huntSkill.findMany({
        where,
        include: { cweMappings: true },
        orderBy: [{ category: "asc" }, { name: "asc" }],
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
      prisma.huntSkill.count({ where }),
      prisma.huntSkill.groupBy({ by: ["category"], _count: true }),
      prisma.huntSkill.aggregate({
        _count: true,
        _max: { lastSyncedAt: true },
      }),
    ]);

    const activeCount = await prisma.huntSkill.count({ where: { isActive: true } });
    const cweCount = await prisma.huntSkillCwe.count();

    return NextResponse.json({
      success: true,
      skills,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
      },
      categories: categories.map((c: { category: string; _count: number }) => ({ category: c.category, count: c._count })),
      stats: {
        total: stats._count,
        active: activeCount,
        inactive: stats._count - activeCount,
        cweMappings: cweCount,
        lastSync: stats._max.lastSyncedAt,
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error al obtener skills";
    console.error("Error fetching knowledge:", error);
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await req.json();

    const { skillId, isActive, cweMappings } = body as {
      skillId?: string;
      isActive?: boolean;
      cweMappings?: { cweId: string; relevance: string }[];
    };

    if (!skillId) {
      return NextResponse.json({ success: false, error: "skillId requerido" }, { status: 400 });
    }

    // Toggle active status
    if (typeof isActive === "boolean") {
      await prisma.huntSkill.update({
        where: { id: skillId },
        data: { isActive },
      });
    }

    // Update CWE mappings if provided
    if (cweMappings && Array.isArray(cweMappings)) {
      // Remove existing mappings
      await prisma.huntSkillCwe.deleteMany({ where: { skillId } });
      // Create new mappings
      for (const mapping of cweMappings) {
        await prisma.huntSkillCwe.create({
          data: {
            skillId,
            cweId: mapping.cweId,
            relevance: mapping.relevance || "PRIMARY",
          },
        });
      }
      // Also update the cweIds JSON field
      await prisma.huntSkill.update({
        where: { id: skillId },
        data: { cweIds: cweMappings.map((m) => m.cweId) },
      });
    }

    const updated = await prisma.huntSkill.findUnique({
      where: { id: skillId },
      include: { cweMappings: true },
    });

    return NextResponse.json({
      success: true,
      skill: updated,
      message: "Skill actualizado exitosamente",
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error al actualizar skill";
    console.error("Error updating knowledge:", error);
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}

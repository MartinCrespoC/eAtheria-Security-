import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * PATCH /api/applications/[id] - Update application
 * DELETE /api/applications/[id] - Soft delete application
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;
    const body = await request.json();
    const { name, description, language, framework, repoUrl } = body;

    const app = await prisma.application.findFirst({
      where: { id, companyId: session.user.companyId },
    });

    if (!app) {
      return NextResponse.json({ error: "Aplicación no encontrada" }, { status: 404 });
    }

    const data: Record<string, unknown> = {};
    if (name?.trim()) data.name = name.trim();
    if (description !== undefined) data.description = description?.trim() || null;
    if (language) data.language = language;
    if (framework) data.framework = framework;
    if (repoUrl !== undefined) data.repoUrl = repoUrl || null;

    const updated = await prisma.application.update({
      where: { id },
      data,
    });

    return NextResponse.json(updated);
  } catch (error) {
    console.error("Error updating application:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    const app = await prisma.application.findFirst({
      where: { id, companyId: session.user.companyId },
    });

    if (!app) {
      return NextResponse.json({ error: "Aplicación no encontrada" }, { status: 404 });
    }

    // Soft delete: mark as inactive
    await prisma.application.update({
      where: { id },
      data: { isActive: false },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "DELETE",
        entityType: "Application",
        entityId: id,
        oldValues: { name: app.name },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({ success: true, message: "Aplicación eliminada" });
  } catch (error) {
    console.error("Error deleting application:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ userId: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { userId } = await params;
    const body = await request.json();
    const { block } = body;

    if (typeof block !== "boolean") {
      return NextResponse.json(
        { error: "El campo 'block' debe ser un booleano" },
        { status: 400 }
      );
    }

    // Verify target user belongs to same company
    const targetUser = await prisma.user.findFirst({
      where: { id: userId, companyId: session.user.companyId },
    });

    if (!targetUser) {
      return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
    }

    // Prevent self-blocking
    if (userId === session.user.id) {
      return NextResponse.json(
        { error: "No puedes bloquearte a ti mismo" },
        { status: 400 }
      );
    }

    // Update user block status
    await prisma.user.update({
      where: { id: userId },
      data: {
        isBlocked: block,
        blockedAt: block ? new Date() : null,
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: block ? "BLOCK" : "UNBLOCK",
        entityType: "User",
        entityId: userId,
        newValues: { isBlocked: block },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({
      success: true,
      message: block ? "Usuario bloqueado" : "Usuario desbloqueado",
    });
  } catch (error) {
    console.error("Error toggling user block:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

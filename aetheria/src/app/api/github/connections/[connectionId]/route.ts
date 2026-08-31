import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ connectionId: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { connectionId } = await params;

    const connection = await prisma.githubConnection.findFirst({
      where: { id: connectionId, companyId: session.user.companyId },
    });

    if (!connection) {
      return NextResponse.json({ error: "Conexión no encontrada" }, { status: 404 });
    }

    // Delete repositories linked to this connection first
    await prisma.githubRepository.deleteMany({
      where: { connectionId },
    });

    // Delete the connection
    await prisma.githubConnection.delete({
      where: { id: connectionId },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "DELETE",
        entityType: "GitHubConnection",
        entityId: connectionId,
        oldValues: { name: connection.name },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error deleting GitHub connection:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

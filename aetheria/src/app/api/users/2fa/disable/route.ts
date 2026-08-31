import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * POST /api/users/2fa/disable
 * Disable 2FA for the current user (requires password confirmation)
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await request.json();
    const { password } = body;

    if (!password) {
      return NextResponse.json(
        { error: "Se requiere confirmación de contraseña" },
        { status: 400 }
      );
    }

    // Verify user has 2FA enabled
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
    });

    if (!user) {
      return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
    }

    if (!user.twoFactorEnabled) {
      return NextResponse.json(
        { error: "2FA no está activado" },
        { status: 400 }
      );
    }

    // Verify password (SRP-based systems may skip this, but for safety)
    // For SRP users without passwordHash, we trust the session
    if (user.passwordHash) {
      const { verifyPassword } = await import("@/lib/crypto");
      const valid = await verifyPassword(password, user.passwordHash);
      if (!valid) {
        return NextResponse.json(
          { error: "Contraseña incorrecta" },
          { status: 403 }
        );
      }
    }

    // Disable 2FA
    await prisma.user.update({
      where: { id: session.user.id },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorBackupCodes: [],
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "DISABLE_2FA",
        entityType: "User",
        entityId: session.user.id,
        userId: session.user.id,
        companyId: session.user.companyId || null,
      },
    });

    return NextResponse.json({ success: true, message: "2FA desactivado correctamente" });
  } catch (error) {
    console.error("Error disabling 2FA:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

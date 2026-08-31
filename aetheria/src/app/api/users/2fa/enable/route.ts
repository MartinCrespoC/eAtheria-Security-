import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { verify2FAToken } from "@/lib/totp";
import crypto from "crypto";

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await request.json();
    const { code } = body;

    if (!code) {
      return NextResponse.json({ error: "Código requerido" }, { status: 400 });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { twoFactorSecret: true },
    });

    if (!user?.twoFactorSecret) {
      return NextResponse.json(
        { error: "Primero debes configurar 2FA" },
        { status: 400 }
      );
    }

    const isValid = verify2FAToken(user.twoFactorSecret, code);
    if (!isValid) {
      return NextResponse.json(
        { error: "Código inválido" },
        { status: 400 }
      );
    }

    // Generate backup codes
    const backupCodes = Array.from({ length: 8 }, () =>
      crypto.randomBytes(4).toString("hex")
    );

    await prisma.user.update({
      where: { id: session.user.id },
      data: {
        twoFactorEnabled: true,
        twoFactorBackupCodes: backupCodes,
      },
    });

    await prisma.auditLog.create({
      data: {
        action: "2FA_ENABLED",
        entityType: "User",
        entityId: session.user.id,
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({ success: true, backupCodes });
  } catch (error) {
    console.error("2FA enable error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

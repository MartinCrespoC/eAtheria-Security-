import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { verifyPassword, hashPassword } from "@/lib/crypto";
import { derivePrivateKey, deriveVerifier } from "secure-remote-password/client";
import { generateSrpCredentials } from "@/lib/auth/srp-credentials";

export async function PATCH(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await request.json();
    const { currentPassword, newPassword } = body;

    if (!currentPassword || !newPassword) {
      return NextResponse.json(
        { error: "Contraseña actual y nueva son obligatorias" },
        { status: 400 }
      );
    }

    if (newPassword.length < 8) {
      return NextResponse.json(
        { error: "La nueva contraseña debe tener al menos 8 caracteres" },
        { status: 400 }
      );
    }

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { email: true, passwordHash: true, srpSalt: true, srpVerifier: true },
    });

    if (!user?.passwordHash && !(user?.srpSalt && user?.srpVerifier)) {
      return NextResponse.json({ error: "Error de autenticación" }, { status: 400 });
    }

    // Verify current password: bcrypt for legacy users, SRP verifier
    // recompute (deterministic: same salt+email+password -> same verifier)
    // for zero-knowledge users.
    let isValid = false;
    if (user.passwordHash) {
      isValid = await verifyPassword(currentPassword, user.passwordHash);
    }
    if (!isValid && user.srpSalt && user.srpVerifier && user.email) {
      const privateKey = derivePrivateKey(
        user.srpSalt,
        user.email.toLowerCase().trim(),
        currentPassword
      );
      isValid = deriveVerifier(privateKey) === user.srpVerifier;
    }

    if (!isValid) {
      return NextResponse.json(
        { error: "Contraseña actual incorrecta" },
        { status: 400 }
      );
    }

    // Rotate BOTH auth methods: new bcrypt hash + fresh SRP salt/verifier,
    // otherwise the old password would keep working via SRP login.
    const newHash = await hashPassword(newPassword);
    const srpCreds = generateSrpCredentials(user.email!, newPassword);
    await prisma.user.update({
      where: { id: session.user.id },
      data: { passwordHash: newHash, ...srpCreds },
    });

    await prisma.auditLog.create({
      data: {
        action: "PASSWORD_CHANGED",
        entityType: "User",
        entityId: session.user.id,
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error changing password:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

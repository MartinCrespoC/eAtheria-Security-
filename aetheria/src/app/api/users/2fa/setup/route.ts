import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generate2FASecret, generateQRCode } from "@/lib/totp";

export async function POST() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { secret, otpauthUrl } = generate2FASecret(session.user.email || "user");
    const qrCode = await generateQRCode(otpauthUrl);

    // Store secret temporarily (not yet enabled)
    await prisma.user.update({
      where: { id: session.user.id },
      data: { twoFactorSecret: secret },
    });

    return NextResponse.json({ qrCode, secret });
  } catch (error) {
    console.error("2FA setup error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

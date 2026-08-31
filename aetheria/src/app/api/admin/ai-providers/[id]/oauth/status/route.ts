import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { pollForToken } from "@/lib/ai/auth/oauth-device";
import { encrypt } from "@/lib/ai/encryption";
import { COPILOT_OAUTH_CONFIG } from "@/lib/ai/auth/copilot-auth";
import { GOOGLE_OAUTH_CONFIG } from "@/lib/ai/auth/google-auth";

// GET — poll OAuth status
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;

    const provider = await prisma.aIProvider.findUnique({ where: { id } });
    if (!provider) {
      return NextResponse.json({ error: "Provider no encontrado" }, { status: 404 });
    }

    const cfg = provider.config as Record<string, unknown> | null;
    const deviceCode = cfg?.pendingDeviceCode as string | undefined;

    if (!deviceCode) {
      return NextResponse.json({ status: "no_pending", message: "No hay flujo OAuth pendiente" });
    }

    // Select OAuth config
    let oauthConfig;
    if (provider.type === "copilot") {
      oauthConfig = COPILOT_OAUTH_CONFIG;
    } else if (provider.type === "google-gemini-oauth") {
      oauthConfig = GOOGLE_OAUTH_CONFIG;
    } else {
      return NextResponse.json({ status: "error", message: "Tipo no soportado" });
    }

    const token = await pollForToken(oauthConfig, deviceCode);

    if (!token) {
      // Still waiting for user authorization
      return NextResponse.json({ status: "pending", message: "Esperando autorización del usuario..." });
    }

    // Success! Store encrypted tokens
    const expiresAt = new Date(Date.now() + token.expiresIn * 1000).toISOString();

    const newConfig = {
      authType: "oauth",
      accessToken: encrypt(token.accessToken),
      refreshToken: token.refreshToken ? encrypt(token.refreshToken) : null,
      expiresAt,
      scope: token.scope || oauthConfig.scope,
      clientId: oauthConfig.clientId,
      tokenUrl: oauthConfig.tokenUrl,
    };

    await prisma.aIProvider.update({
      where: { id },
      data: {
        config: JSON.parse(JSON.stringify(newConfig)),
        isActive: true,
      },
    });

    return NextResponse.json({ status: "connected", message: "¡Conectado exitosamente!" });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });

    // Handle known OAuth errors
    if (error instanceof Error && error.message.includes("expired")) {
      return NextResponse.json({ status: "expired", message: "Código expirado — reiniciar" });
    }
    if (error instanceof Error && error.message.includes("denied")) {
      return NextResponse.json({ status: "denied", message: "Autorización denegada por el usuario" });
    }

    console.error("Error polling OAuth status:", error);
    return NextResponse.json({ status: "error", message: "Error al verificar estado" });
  }
}

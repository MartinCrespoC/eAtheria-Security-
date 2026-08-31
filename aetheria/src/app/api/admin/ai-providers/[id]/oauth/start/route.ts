import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { startDeviceCodeFlow } from "@/lib/ai/auth/oauth-device";
import { COPILOT_OAUTH_CONFIG } from "@/lib/ai/auth/copilot-auth";
import { GOOGLE_OAUTH_CONFIG } from "@/lib/ai/auth/google-auth";

// POST — start OAuth device code flow
export async function POST(
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

    if (provider.authType !== "oauth") {
      return NextResponse.json({ error: "Este provider no usa OAuth" }, { status: 400 });
    }

    // Select OAuth config based on provider type
    let oauthConfig;
    if (provider.type === "copilot") {
      oauthConfig = COPILOT_OAUTH_CONFIG;
    } else if (provider.type === "google-gemini-oauth") {
      oauthConfig = GOOGLE_OAUTH_CONFIG;
    } else {
      return NextResponse.json({ error: "OAuth no soportado para este tipo" }, { status: 400 });
    }

    const deviceCode = await startDeviceCodeFlow(oauthConfig);

    // Store device code in provider config temporarily for polling
    await prisma.aIProvider.update({
      where: { id },
      data: {
        config: {
          ...(provider.config as Record<string, unknown> || {}),
          pendingDeviceCode: deviceCode.deviceCode,
          oauthProvider: provider.type,
        },
      },
    });

    return NextResponse.json({
      userCode: deviceCode.userCode,
      verificationUri: deviceCode.verificationUri,
      expiresIn: deviceCode.expiresIn,
      interval: deviceCode.interval,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error starting OAuth flow:", error);
    return NextResponse.json({ error: "Error al iniciar flujo OAuth" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/ai/encryption";
import { getAdapter } from "@/lib/ai/registry";

// POST — test provider connection
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

    if (!provider.apiKeyEnc && provider.authType === "api_key") {
      return NextResponse.json({ ok: false, error: "No hay API key configurada" });
    }

    let apiKey = "";
    if (provider.apiKeyEnc) {
      apiKey = decrypt(provider.apiKeyEnc);
    } else if (provider.authType === "oauth") {
      const cfg = provider.config as Record<string, unknown> | null;
      if (cfg?.accessToken) {
        apiKey = decrypt(cfg.accessToken as string);
      } else {
        return NextResponse.json({ ok: false, error: "No hay token OAuth — conectar primero" });
      }
    }

    const adapter = getAdapter(provider.type, provider.slug);
    const result = await adapter.testConnection({
      apiKey,
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
    });

    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error testing provider:", error);
    return NextResponse.json({ ok: false, error: "Error interno al testear" });
  }
}

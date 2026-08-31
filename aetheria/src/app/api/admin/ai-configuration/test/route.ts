import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/ai/encryption";
import { getAdapter } from "@/lib/ai/registry";
import { checkProviderHealth } from "@/lib/ai/health-monitor";

/**
 * POST /api/admin/ai-configuration/test
 * Test a specific provider connection.
 * Body: { providerId }
 * If providerId is omitted, tests the raw config provided in body.config.
 */
export async function POST(request: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await request.json();
    const { providerId } = body;

    if (!providerId) {
      return NextResponse.json({ error: "providerId es requerido" }, { status: 400 });
    }

    const provider = await prisma.aIProvider.findUnique({ where: { id: providerId } });
    if (!provider) {
      return NextResponse.json({ error: "Provider no encontrado" }, { status: 404 });
    }

    // Run a quick connection test via the adapter
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
    } else if (!apiKey) {
      return NextResponse.json({ ok: false, error: "No hay API key configurada" });
    }

    const adapter = getAdapter(provider.type, provider.slug);
    const result = await adapter.testConnection({
      apiKey,
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
    });

    // Also run a health check to record the result
    await checkProviderHealth(providerId);

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

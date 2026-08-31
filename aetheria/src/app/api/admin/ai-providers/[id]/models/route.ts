import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/ai/encryption";
import { getAdapter } from "@/lib/ai/registry";

// GET — fetch available models from provider API
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

    let apiKey = "";
    if (provider.apiKeyEnc) {
      apiKey = decrypt(provider.apiKeyEnc);
    } else if (provider.authType === "oauth") {
      const cfg = provider.config as Record<string, unknown> | null;
      if (cfg?.accessToken) {
        apiKey = decrypt(cfg.accessToken as string);
      }
    }

    if (!apiKey) {
      return NextResponse.json({ error: "No hay credenciales configuradas" }, { status: 400 });
    }

    const adapter = getAdapter(provider.type, provider.slug);
    const models = await adapter.listModels({
      apiKey,
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
    });

    // Check which are already added
    const existingModels = await prisma.aIModel.findMany({
      where: { providerId: provider.id },
      select: { modelId: true },
    });
    const existingIds = new Set(existingModels.map((m) => m.modelId));

    const withStatus = models.map((m) => ({
      ...m,
      alreadyAdded: existingIds.has(m.modelId),
    }));

    return NextResponse.json(withStatus);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching provider models:", error);
    return NextResponse.json({ error: "Error al obtener modelos" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { encrypt } from "@/lib/ai/encryption";

// GET — list all providers
export async function GET() {
  try {
    await requireSystemAdmin();
    const providers = await prisma.aIProvider.findMany({
      orderBy: [{ isActive: "desc" }, { name: "asc" }],
      include: { _count: { select: { models: true } } },
    });

    // Don't expose encrypted keys — just indicate if they exist
    const sanitized = providers.map((p) => ({
      ...p,
      apiKeyEnc: undefined,
      hasApiKey: !!p.apiKeyEnc,
      config: p.authType === "oauth"
        ? { authType: "oauth", hasToken: !!(p.config as Record<string, unknown>)?.accessToken }
        : p.config,
    }));

    return NextResponse.json(sanitized);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

// POST — create a new provider
export async function POST(request: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await request.json();
    const { slug, name, type, baseUrl, apiKey, authType, config } = body;

    if (!slug || !name || !type) {
      return NextResponse.json({ error: "slug, name y type son requeridos" }, { status: 400 });
    }

    // Check for duplicate slug
    const existing = await prisma.aIProvider.findUnique({ where: { slug } });
    if (existing) {
      return NextResponse.json({ error: `Provider "${slug}" ya existe` }, { status: 409 });
    }

    const provider = await prisma.aIProvider.create({
      data: {
        slug,
        name,
        type,
        baseUrl: baseUrl || null,
        apiKeyEnc: apiKey ? encrypt(apiKey) : null,
        authType: authType || "api_key",
        isActive: !!apiKey,
        config: config || null,
      },
    });

    return NextResponse.json({ ...provider, apiKeyEnc: undefined, hasApiKey: !!provider.apiKeyEnc }, { status: 201 });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error creating AI provider:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

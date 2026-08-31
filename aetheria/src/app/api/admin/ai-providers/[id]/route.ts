import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { encrypt } from "@/lib/ai/encryption";

// PATCH — update provider
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;
    const body = await request.json();

    const updateData: Record<string, unknown> = {};

    if (body.name !== undefined) updateData.name = body.name;
    if (body.baseUrl !== undefined) updateData.baseUrl = body.baseUrl || null;
    if (body.config !== undefined) updateData.config = body.config;
    if (body.authType !== undefined) updateData.authType = body.authType;

    // Encrypt new API key if provided
    if (body.apiKey !== undefined && body.apiKey !== "") {
      updateData.apiKeyEnc = encrypt(body.apiKey);
    }

    // Encrypt service account JSON (Vertex AI)
    if (body.serviceAccountJson !== undefined && body.serviceAccountJson !== "") {
      updateData.apiKeyEnc = encrypt(body.serviceAccountJson);
    }

    // If activating this provider, deactivate all others (only one active at a time per company)
    if (body.isActive !== undefined) {
      updateData.isActive = body.isActive;

      if (body.isActive === true) {
        // Deactivate all other providers first
        await prisma.aIProvider.updateMany({
          where: { id: { not: id } },
          data: { isActive: false },
        });
      }
    }

    const provider = await prisma.aIProvider.update({
      where: { id },
      data: updateData,
    });

    return NextResponse.json({ ...provider, apiKeyEnc: undefined, hasApiKey: !!provider.apiKeyEnc });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating AI provider:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

// DELETE — remove provider
export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;

    // Check if provider has models
    const modelCount = await prisma.aIModel.count({ where: { providerId: id } });
    if (modelCount > 0) {
      return NextResponse.json(
        { error: `No se puede eliminar: tiene ${modelCount} modelo(s) asociado(s)` },
        { status: 400 }
      );
    }

    await prisma.aIProvider.delete({ where: { id } });
    return NextResponse.json({ ok: true });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error deleting AI provider:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

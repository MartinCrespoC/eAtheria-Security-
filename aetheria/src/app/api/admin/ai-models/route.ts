import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

// GET — list all models in DB
export async function GET() {
  try {
    await requireSystemAdmin();
    const models = await prisma.aIModel.findMany({
      orderBy: [{ isDefault: "desc" }, { name: "asc" }],
    });
    return NextResponse.json(models);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

// POST — create a new model
export async function POST(request: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await request.json();
    const { name, provider, modelId, inputTokenCost, outputTokenCost, maxInputTokens, maxOutputTokens, isDefault, providerId } = body;

    if (!name || !modelId) {
      return NextResponse.json({ error: "name y modelId son requeridos" }, { status: 400 });
    }

    // If setting as default, unset current default first
    if (isDefault) {
      await prisma.aIModel.updateMany({
        where: { isDefault: true },
        data: { isDefault: false },
      });
    }

    const model = await prisma.aIModel.create({
      data: {
        name,
        provider: provider || "gemini",
        modelId,
        inputTokenCost: inputTokenCost || 0,
        outputTokenCost: outputTokenCost || 0,
        maxInputTokens: maxInputTokens || 1_000_000,
        maxOutputTokens: maxOutputTokens || 65536,
        isDefault: isDefault || false,
        isActive: true,
        providerId: providerId || null,
      },
    });

    return NextResponse.json(model, { status: 201 });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error creating AI model:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

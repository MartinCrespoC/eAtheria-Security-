import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

// PATCH — update model (set default, toggle active, edit costs)
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;
    const body = await request.json();

    // If setting as default, unset current default first
    if (body.isDefault === true) {
      await prisma.aIModel.updateMany({
        where: { isDefault: true },
        data: { isDefault: false },
      });
    }

    const model = await prisma.aIModel.update({
      where: { id },
      data: {
        ...(body.name !== undefined && { name: body.name }),
        ...(body.modelId !== undefined && { modelId: body.modelId }),
        ...(body.provider !== undefined && { provider: body.provider }),
        ...(body.inputTokenCost !== undefined && { inputTokenCost: body.inputTokenCost }),
        ...(body.outputTokenCost !== undefined && { outputTokenCost: body.outputTokenCost }),
        ...(body.maxInputTokens !== undefined && { maxInputTokens: body.maxInputTokens }),
        ...(body.maxOutputTokens !== undefined && { maxOutputTokens: body.maxOutputTokens }),
        ...(body.isActive !== undefined && { isActive: body.isActive }),
        ...(body.isDefault !== undefined && { isDefault: body.isDefault }),
      },
    });

    return NextResponse.json(model);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error updating AI model:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

// DELETE — remove model
export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;

    // Check for token usage references
    const usageCount = await prisma.tokenUsage.count({ where: { modelId: id } });
    if (usageCount > 0) {
      // Deactivate instead of deleting
      await prisma.aIModel.update({ where: { id }, data: { isActive: false } });
      return NextResponse.json({ message: "Modelo desactivado (tiene registros de uso)" });
    }

    await prisma.aIModel.delete({ where: { id } });
    return NextResponse.json({ message: "Modelo eliminado" });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error deleting AI model:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/analyses/[id]/threat-model
 * Retrieve the threat model generated for an analysis
 */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    // Verify analysis belongs to user's company
    const analysis = await prisma.analysis.findFirst({
      where: {
        id,
        appVersion: { application: { companyId: session.user.companyId } },
      },
      select: { id: true },
    });

    if (!analysis) {
      return NextResponse.json({ error: "Análisis no encontrado" }, { status: 404 });
    }

    const threatModel = await prisma.threatModel.findUnique({
      where: { analysisId: id },
    });

    if (!threatModel) {
      return NextResponse.json(
        { error: "No se generó modelo de amenazas para este análisis" },
        { status: 404 }
      );
    }

    return NextResponse.json(threatModel);
  } catch (error) {
    console.error("Error fetching threat model:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

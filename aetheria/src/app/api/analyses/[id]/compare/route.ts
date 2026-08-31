import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { compareScans } from "@/lib/methodology";

/**
 * GET /api/analyses/[id]/compare?with=<prevAnalysisId>
 * Compare current analysis with a previous one using root-cause matching
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id: currAnalysisId } = await params;
    const { searchParams } = new URL(request.url);
    const prevAnalysisId = searchParams.get("with");

    if (!prevAnalysisId) {
      return NextResponse.json(
        { error: "Se requiere parámetro 'with' (ID del análisis anterior)" },
        { status: 400 }
      );
    }

    // Verify both analyses belong to user's company
    const [currAnalysis, prevAnalysis] = await Promise.all([
      prisma.analysis.findFirst({
        where: {
          id: currAnalysisId,
          appVersion: { application: { companyId: session.user.companyId } },
        },
        select: { id: true, status: true },
      }),
      prisma.analysis.findFirst({
        where: {
          id: prevAnalysisId,
          appVersion: { application: { companyId: session.user.companyId } },
        },
        select: { id: true, status: true },
      }),
    ]);

    if (!currAnalysis || !prevAnalysis) {
      return NextResponse.json({ error: "Análisis no encontrado" }, { status: 404 });
    }

    const result = await compareScans(prevAnalysisId, currAnalysisId, session.user.companyId);

    if (!result) {
      return NextResponse.json(
        { error: "No hay hallazgos para comparar" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      previousAnalysisId: prevAnalysisId,
      currentAnalysisId: currAnalysisId,
      ...result,
    });
  } catch (error) {
    console.error("Error comparing scans:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

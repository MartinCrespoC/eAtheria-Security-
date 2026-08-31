import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generateHardeningProposal } from "@/lib/methodology";

/**
 * POST /api/analyses/[id]/hardening
 * Generate structural hardening proposals for an analysis
 */
export async function POST(
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
      select: { id: true, status: true },
    });

    if (!analysis) {
      return NextResponse.json({ error: "Análisis no encontrado" }, { status: 404 });
    }

    if (analysis.status !== "COMPLETED") {
      return NextResponse.json(
        { error: "El análisis debe estar completado para generar propuestas de hardening" },
        { status: 400 }
      );
    }

    const proposal = await generateHardeningProposal(id, session.user.companyId);

    if (!proposal) {
      return NextResponse.json(
        { error: "No se pudieron generar propuestas (sin hallazgos o respuesta IA vacía)" },
        { status: 502 }
      );
    }

    return NextResponse.json({
      analysisId: id,
      opportunities: proposal.opportunities,
      generatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Error generating hardening proposal:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

/**
 * GET /api/analyses/[id]/hardening
 * List existing hardening proposals for an analysis
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

    const proposals = await prisma.hardeningProposal.findMany({
      where: {
        analysisId: id,
        companyId: session.user.companyId,
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(proposals);
  } catch (error) {
    console.error("Error fetching hardening proposals:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generateWriteup } from "@/lib/methodology";

/**
 * POST /api/vulnerabilities/[id]/writeup
 * Generate a disclosure-quality vulnerability writeup
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

    // Verify vulnerability belongs to user's company
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id,
        analysis: { appVersion: { application: { companyId: session.user.companyId } } },
      },
      select: { id: true, title: true },
    });

    if (!vuln) {
      return NextResponse.json({ error: "Vulnerabilidad no encontrada" }, { status: 404 });
    }

    const writeup = await generateWriteup(id, session.user.companyId);

    if (!writeup) {
      return NextResponse.json(
        { error: "No se pudo generar el writeup (respuesta IA vacía)" },
        { status: 502 }
      );
    }

    return NextResponse.json({
      vulnerabilityId: id,
      title: vuln.title,
      writeup,
      generatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Error generating writeup:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

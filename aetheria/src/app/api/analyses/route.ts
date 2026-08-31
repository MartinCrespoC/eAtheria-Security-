import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import type { ScanLevel } from "@/lib/analysis/scan-knowledge";
import { triggerAnalysis } from "@/lib/analysis/trigger";

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const companyId = session.user.companyId;
    const analyses = await prisma.analysis.findMany({
      where: companyId
        ? { appVersion: { application: { companyId } } }
        : undefined,
      include: {
        appVersion: {
          include: { application: { select: { id: true, name: true } } },
        },
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    const serialized = JSON.parse(JSON.stringify(analyses, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value
    ));

    return NextResponse.json(serialized);
  } catch (error) {
    console.error("Error fetching analyses:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    if (!session.user.companyId) {
      return NextResponse.json(
        { error: "No tienes una empresa asociada" },
        { status: 400 }
      );
    }

    const body = await request.json();
    const { appVersionId, scanTypes, aiValidation, scanLevel } = body;

    if (!appVersionId) {
      return NextResponse.json(
        { error: "Se requiere una versión de aplicación" },
        { status: 400 }
      );
    }

    // Verify the version belongs to the user's company
    const version = await prisma.appVersion.findUnique({
      where: { id: appVersionId },
      include: { application: true },
    });

    if (!version || version.application.companyId !== session.user.companyId) {
      return NextResponse.json({ error: "Versión no encontrada" }, { status: 404 });
    }

    // Individual mode: no licensing limits — all scan levels allowed
    const requestedLevel: ScanLevel = ["STATIC", "LIGHTWEIGHT", "DEEP"].includes(scanLevel) ? scanLevel : "STATIC";

    const analysis = await prisma.analysis.create({
      data: {
        appVersionId,
        scanTypes: scanTypes || ["SAST", "SCA"],
        scanLevel: requestedLevel,
        aiValidation: aiValidation !== false,
        triggeredBy: session.user.id,
        status: "PENDING",
      },
    });

    // Trigger async analysis (in production, use a queue)
    triggerAnalysis(analysis.id).catch(console.error);

    // Serialize safely (BigInt fields can't be JSON.stringified)
    const serialized = JSON.parse(JSON.stringify(analysis, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value
    ));

    return NextResponse.json(serialized, { status: 201 });
  } catch (error) {
    console.error("Error creating analysis:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

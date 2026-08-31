import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;

    // Verify application belongs to user's company
    const app = await prisma.application.findFirst({
      where: { id, companyId: session.user.companyId },
    });

    if (!app) {
      return NextResponse.json({ error: "Aplicación no encontrada" }, { status: 404 });
    }

    const body = await request.json();
    const { version, branch, sourceType } = body;

    if (!version?.trim()) {
      return NextResponse.json(
        { error: "La versión es obligatoria" },
        { status: 400 }
      );
    }

    // Check for duplicate version
    const existing = await prisma.appVersion.findUnique({
      where: { applicationId_version: { applicationId: id, version: version.trim() } },
    });

    if (existing) {
      return NextResponse.json(
        { error: "Esta versión ya existe" },
        { status: 409 }
      );
    }

    const appVersion = await prisma.appVersion.create({
      data: {
        version: version.trim(),
        branch: branch?.trim() || null,
        sourceType: sourceType || "ZIP_UPLOAD",
        applicationId: id,
      },
    });

    await prisma.auditLog.create({
      data: {
        action: "CREATE",
        entityType: "AppVersion",
        entityId: appVersion.id,
        newValues: { version: appVersion.version, applicationId: id },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json(appVersion, { status: 201 });
  } catch (error) {
    console.error("Error creating version:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

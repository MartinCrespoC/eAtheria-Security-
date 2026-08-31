import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, "")
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-");
}

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const companyId = session.user.companyId;
    const applications = await prisma.application.findMany({
      where: companyId ? { companyId } : undefined,
      include: {
        versions: {
          orderBy: { createdAt: "desc" },
          take: 1,
        },
        _count: { select: { versions: true } },
      },
      orderBy: { updatedAt: "desc" },
    });

    return NextResponse.json(applications);
  } catch (error) {
    console.error("Error fetching applications:", error);
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
    const { name, description, language, framework, repoUrl } = body;

    if (!name || name.trim().length < 2) {
      return NextResponse.json(
        { error: "El nombre es obligatorio (mín. 2 caracteres)" },
        { status: 400 }
      );
    }

    const slug = slugify(name);

    // Check uniqueness
    const existing = await prisma.application.findUnique({
      where: {
        companyId_slug: {
          companyId: session.user.companyId,
          slug,
        },
      },
    });

    if (existing) {
      return NextResponse.json(
        { error: "Ya existe una aplicación con ese nombre" },
        { status: 409 }
      );
    }

    const app = await prisma.application.create({
      data: {
        name: name.trim(),
        slug,
        description: description?.trim() || null,
        language: language?.trim() || null,
        framework: framework?.trim() || null,
        repoUrl: repoUrl?.trim() || null,
        companyId: session.user.companyId,
      },
    });

    // Create audit log
    await prisma.auditLog.create({
      data: {
        action: "APPLICATION_CREATED",
        entityType: "Application",
        entityId: app.id,
        newValues: { name: app.name, slug: app.slug },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json(app, { status: 201 });
  } catch (error) {
    console.error("Error creating application:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

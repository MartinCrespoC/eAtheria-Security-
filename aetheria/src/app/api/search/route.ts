import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/search?q=term
 * Global search across applications, analyses, and vulnerabilities (company-scoped)
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const q = searchParams.get("q")?.trim();

    if (!q || q.length < 3) {
      return NextResponse.json({ results: [] });
    }

    const companyId = session.user.companyId;
    const take = 5;

    // Search applications
    const applications = await prisma.application.findMany({
      where: {
        companyId,
        name: { contains: q, mode: "insensitive" },
      },
      select: { id: true, name: true, slug: true },
      take,
    });

    // Search analyses (via application relation)
    const analyses = await prisma.analysis.findMany({
      where: {
        appVersion: {
          application: {
            companyId,
            name: { contains: q, mode: "insensitive" },
          },
        },
      },
      select: {
        id: true,
        status: true,
        createdAt: true,
        appVersion: { select: { version: true, application: { select: { name: true } } } },
      },
      take,
      orderBy: { createdAt: "desc" },
    });

    // Search vulnerabilities
    const vulnerabilities = await prisma.vulnerability.findMany({
      where: {
        analysis: { appVersion: { application: { companyId } } },
        OR: [
          { title: { contains: q, mode: "insensitive" } },
          { cweId: { contains: q, mode: "insensitive" } },
        ],
      },
      select: { id: true, title: true, severity: true, cweId: true },
      take,
    });

    const results = [
      ...applications.map((a) => ({
        type: "application" as const,
        id: a.id,
        title: a.name,
        subtitle: `@${a.slug}`,
        href: `/dashboard/applications/${a.id}`,
      })),
      ...analyses.map((a) => ({
        type: "analysis" as const,
        id: a.id,
        title: `${a.appVersion.application.name} — ${a.appVersion.version}`,
        subtitle: `${a.status} · ${new Date(a.createdAt).toLocaleDateString()}`,
        href: `/dashboard/analyses/${a.id}`,
      })),
      ...vulnerabilities.map((v) => ({
        type: "vulnerability" as const,
        id: v.id,
        title: v.title,
        subtitle: `${v.severity} · ${v.cweId || "N/A"}`,
        href: `/dashboard/vulnerabilities`,
      })),
    ];

    return NextResponse.json({ results });
  } catch (error) {
    console.error("Search error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

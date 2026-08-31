import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey, hasScope } from "@/lib/api-auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/v1/scan/:id
 * Get analysis status and results
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json(
      { error: "Invalid or expired API key." },
      { status: 401 }
    );
  }

  if (!hasScope(ctx, "analysis:read")) {
    return NextResponse.json(
      { error: "API key does not have 'analysis:read' scope." },
      { status: 403 }
    );
  }

  const { id } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: {
      id,
      appVersion: { application: { companyId: ctx.companyId } },
    },
    include: {
      appVersion: {
        select: {
          version: true,
          branch: true,
          commitHash: true,
          application: { select: { name: true, repoUrl: true } },
        },
      },
      vulnerabilities: {
        select: {
          id: true,
          title: true,
          severity: true,
          category: true,
          filePath: true,
          lineStart: true,
          lineEnd: true,
          description: true,
          smartFix: true,
          fixExplanation: true,
          status: true,
          cweId: true,
        },
        orderBy: [{ severity: "desc" }, { createdAt: "desc" }],
      },
    },
  });

  if (!analysis) {
    return NextResponse.json(
      { error: "Analysis not found." },
      { status: 404 }
    );
  }

  return NextResponse.json({
    id: analysis.id,
    status: analysis.status,
    repository: analysis.appVersion.application.name,
    branch: analysis.appVersion.branch,
    commit: analysis.appVersion.commitHash,
    startedAt: analysis.startedAt,
    completedAt: analysis.completedAt,
    duration: analysis.duration,
    summary: {
      total: analysis.totalIssues,
      critical: analysis.criticalCount,
      high: analysis.highCount,
      medium: analysis.mediumCount,
      low: analysis.lowCount,
      info: analysis.infoCount,
    },
    vulnerabilities: analysis.vulnerabilities.map((v) => ({
      id: v.id,
      title: v.title,
      severity: v.severity,
      category: v.category,
      file: v.filePath,
      line: v.lineStart,
      lineEnd: v.lineEnd,
      description: v.description,
      fix: v.smartFix,
      fixExplanation: v.fixExplanation,
      status: v.status,
      cweId: v.cweId,
    })),
  });
}

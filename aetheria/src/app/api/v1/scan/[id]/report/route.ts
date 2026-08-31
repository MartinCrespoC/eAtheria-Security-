import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey, hasScope } from "@/lib/api-auth";
import { rateLimit, getClientIp } from "@/lib/rate-limit";
import { prisma } from "@/lib/db";
import { buildPdfReport } from "@/lib/export/pdf-report-server";

/**
 * GET /api/v1/scan/{id}/report?format=pdf
 * Server-side detailed PDF report for CI/CD pipelines.
 *
 * Headers:
 *   Authorization: Bearer aeth_xxxxx (scope: analysis:read)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const ip = getClientIp(req.headers);
  const rl = rateLimit(`api:report:${ip}`, { maxRequests: 30, windowMs: 60_000 });
  if (!rl.success) {
    return NextResponse.json({ error: "Rate limit exceeded." }, { status: 429 });
  }

  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json({ error: "Invalid or expired API key." }, { status: 401 });
  }
  if (!hasScope(ctx, "analysis:read")) {
    return NextResponse.json(
      { error: "API key does not have 'analysis:read' scope." },
      { status: 403 }
    );
  }

  const format = req.nextUrl.searchParams.get("format") || "pdf";
  if (format !== "pdf") {
    return NextResponse.json({ error: "Only format=pdf is supported." }, { status: 400 });
  }

  const { id } = await params;
  const analysis = await prisma.analysis.findFirst({
    where: { id, appVersion: { application: { companyId: ctx.companyId } } },
    include: {
      appVersion: { include: { application: { select: { name: true } } } },
      vulnerabilities: {
        select: {
          severity: true, title: true, category: true, cweId: true, owaspTop10: true,
          filePath: true, lineStart: true, confidence: true, description: true,
          smartFix: true, fixExplanation: true, isFalsePositive: true, fpReason: true,
          aiValidated: true, aiConfidence: true,
        },
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
      },
    },
  });

  if (!analysis) {
    return NextResponse.json({ error: "Analysis not found." }, { status: 404 });
  }

  const pdf = buildPdfReport({
    id: analysis.id,
    status: analysis.status,
    scanTypes: analysis.scanTypes,
    duration: analysis.duration,
    totalIssues: analysis.totalIssues,
    criticalCount: analysis.criticalCount,
    highCount: analysis.highCount,
    mediumCount: analysis.mediumCount,
    lowCount: analysis.lowCount,
    infoCount: analysis.infoCount,
    falsePositives: analysis.falsePositives,
    createdAt: analysis.createdAt,
    appVersion: {
      version: analysis.appVersion.version,
      application: { name: analysis.appVersion.application.name },
    },
    vulnerabilities: analysis.vulnerabilities,
  });

  const appName = analysis.appVersion.application.name.replace(/\s+/g, "_");
  return new NextResponse(new Uint8Array(pdf), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="EATHERIA_Report_${appName}_v${analysis.appVersion.version}.pdf"`,
    },
  });
}

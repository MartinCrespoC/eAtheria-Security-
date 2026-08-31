import { NextRequest } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generateSarifReport } from "@/lib/export/sarif-report";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user?.companyId) {
    return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401 });
  }

  const { id } = await params;

  // Verify ownership
  const analysis = await prisma.analysis.findFirst({
    where: { id, appVersion: { application: { companyId: session.user.companyId } } },
    select: {
      id: true,
      status: true,
      appVersion: {
        select: { version: true, application: { select: { name: true } } },
      },
    },
  });

  if (!analysis) {
    return new Response(JSON.stringify({ error: "Análisis no encontrado" }), { status: 404 });
  }

  // Get all vulnerabilities for this analysis
  const vulns = await prisma.vulnerability.findMany({
    where: { analysisId: id, isFalsePositive: false },
    select: {
      cweId: true,
      category: true,
      severity: true,
      owaspTop10: true,
      title: true,
      description: true,
      filePath: true,
      lineStart: true,
      lineEnd: true,
      codeSnippet: true,
      confidence: true,
      detectionMethod: true,
    },
  });

  const findings = vulns.map((v) => ({
    cwe: v.cweId || "N/A",
    category: v.category || "Unknown",
    severity: v.severity,
    owasp2021: v.owaspTop10 || "N/A",
    title: v.title,
    description: v.description,
    filePath: v.filePath || "unknown",
    lineStart: v.lineStart || 1,
    lineEnd: v.lineEnd || 1,
    codeSnippet: v.codeSnippet || "",
    confidence: v.confidence === "HIGH" ? 90 : v.confidence === "MEDIUM" ? 70 : 50,
    detectionMethod: v.detectionMethod || "AI",
  }));

  const sarif = generateSarifReport(findings, {
    scanId: id,
    applicationName: analysis.appVersion.application.name,
    scanLevel: "STATIC",
  });

  const filename = `aetheria-scan-${id.slice(0, 8)}.sarif`;

  return new Response(JSON.stringify(sarif, null, 2), {
    headers: {
      "Content-Type": "application/sarif+json",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}

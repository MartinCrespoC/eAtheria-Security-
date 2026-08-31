import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generateCsvReport } from "@/lib/export/csv-report";
import { generateJsonReport } from "@/lib/export/json-report";
import { notifyReportExported } from "@/lib/messaging/company-notifier";

/**
 * GET /api/analyses/{id}/export?format=pdf|xlsx|csv|json|sarif
 * Server-side export for large analyses.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user?.companyId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const format = request.nextUrl.searchParams.get("format") || "json";

  const analysis = await prisma.analysis.findFirst({
    where: {
      id,
      appVersion: { application: { companyId: session.user.companyId } },
    },
    include: {
      appVersion: {
        include: { application: { select: { name: true } } },
      },
      vulnerabilities: {
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
      },
    },
  });

  if (!analysis) {
    return NextResponse.json({ error: "Analysis not found" }, { status: 404 });
  }

  const appName = analysis.appVersion.application.name.replace(/\s+/g, "_");

  // Notify messaging channels that a report is being exported (fire-and-forget)
  notifyReportExported(session.user.companyId, {
    appName: analysis.appVersion.application.name,
    version: analysis.appVersion.version,
    format,
    exportedBy: session.user.email,
  }).catch(() => {});

  switch (format) {
    case "csv": {
      const csv = generateCsvReport(
        analysis.vulnerabilities.map((v) => ({
          severity: v.severity,
          confidence: v.confidence,
          category: v.category,
          title: v.title,
          description: v.description,
          filePath: v.filePath,
          lineStart: v.lineStart,
          cweId: v.cweId,
          cveId: v.cveId,
          owaspTop10: v.owaspTop10,
          detectionMethod: v.detectionMethod,
          deltaStatus: v.deltaStatus,
          isFalsePositive: v.isFalsePositive,
          status: v.status,
          smartFix: v.smartFix,
          rootCause: (v as Record<string, unknown>).rootCause as string | null || null,
          packageName: (v as Record<string, unknown>).packageName as string | null || null,
          packageVersion: (v as Record<string, unknown>).packageVersion as string | null || null,
          ecosystem: (v as Record<string, unknown>).ecosystem as string | null || null,
        }))
      );
      return new NextResponse(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${appName}_hallazgos.csv"`,
        },
      });
    }

    case "json": {
      const json = generateJsonReport({
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
        sbomData: analysis.sbomData,
        appVersion: {
          version: analysis.appVersion.version,
          application: { name: analysis.appVersion.application.name },
        },
        vulnerabilities: analysis.vulnerabilities as unknown as Record<string, unknown>[],
      });
      return new NextResponse(json, {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Disposition": `attachment; filename="${appName}_report.json"`,
        },
      });
    }

    case "sarif": {
      const sarif = buildSarif(analysis);
      return NextResponse.json(sarif, {
        headers: {
          "Content-Disposition": `attachment; filename="${appName}_results.sarif"`,
        },
      });
    }

    case "xlsx":
    case "pdf": {
      // For PDF/Excel, redirect to client-side generation (they use jsPDF/xlsx libs)
      // In production, these would be generated server-side with heavier libs
      return NextResponse.json(
        { message: `Use client-side export for ${format.toUpperCase()}`, format },
        { status: 200 }
      );
    }

    default:
      return NextResponse.json({ error: `Unsupported format: ${format}` }, { status: 400 });
  }
}

function buildSarif(analysis: {
  id: string;
  appVersion: { application: { name: string }; version: string };
  vulnerabilities: {
    id: string;
    severity: string;
    title: string;
    description: string;
    cweId: string | null;
    filePath: string | null;
    lineStart: number | null;
    category: string;
  }[];
}) {
  const rules = new Map<string, { id: string; name: string; description: string }>();
  const results: Record<string, unknown>[] = [];

  for (const vuln of analysis.vulnerabilities) {
    const ruleId = vuln.cweId || vuln.category;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: vuln.title,
        description: vuln.description.slice(0, 500),
      });
    }

    results.push({
      ruleId,
      level: vuln.severity === "CRITICAL" || vuln.severity === "HIGH" ? "error" : vuln.severity === "MEDIUM" ? "warning" : "note",
      message: { text: vuln.description },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: vuln.filePath || "unknown" },
          region: { startLine: vuln.lineStart || 1 },
        },
      }],
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "eAtheria Security",
          version: "1.0.0",
          informationUri: "https://eatheria.security",
          rules: [...rules.values()].map((r) => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.description },
            helpUri: r.id.startsWith("CWE-") ? `https://cwe.mitre.org/data/definitions/${r.id.replace("CWE-", "")}.html` : undefined,
          })),
        },
      },
      results,
    }],
  };
}

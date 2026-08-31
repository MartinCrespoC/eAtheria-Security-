import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

/**
 * GET /api/standards/evidence?runId=...&format=json|csv
 *
 * Generates a classified, downloadable evidence document for a benchmark
 * run — the artifact an auditor asks for ("do you have evidence for these
 * standards?"). Classified by standard, category and CWE with per-case
 * expected/detected outcomes.
 */
export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const runId = request.nextUrl.searchParams.get("runId");
  const format = request.nextUrl.searchParams.get("format") || "json";

  if (!runId) {
    return NextResponse.json({ error: "runId is required" }, { status: 400 });
  }

  const run = await prisma.benchmarkRun.findUnique({
    where: { id: runId },
    include: {
      cases: {
        select: { cweId: true, category: true, expected: true, detected: true, correct: true },
        orderBy: [{ category: "asc" }, { cweId: "asc" }],
      },
    },
  });

  if (!run) {
    return NextResponse.json({ error: "Run not found" }, { status: 404 });
  }

  const generatedAt = new Date().toISOString();
  const pct = (v: number) => `${(v * 100).toFixed(1)}%`;

  // Classify cases: standard → category → cwe → counts
  const byCategory: Record<string, { total: number; correct: number; cwes: Set<string> }> = {};
  for (const c of run.cases) {
    const entry = (byCategory[c.category] ??= { total: 0, correct: 0, cwes: new Set() });
    entry.total++;
    if (c.correct) entry.correct++;
    entry.cwes.add(c.cweId);
  }

  const classification = Object.entries(byCategory)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, v]) => ({
      category,
      cases: v.total,
      correct: v.correct,
      accuracy: v.total > 0 ? Number((v.correct / v.total).toFixed(4)) : 0,
      cweCoverage: [...v.cwes].sort(),
    }));

  const evidence = {
    documentType: "compliance-evidence",
    generatedAt,
    standard: {
      source: run.source,
      kind: run.kind,
      name: run.name,
    },
    run: {
      id: run.id,
      executedAt: run.createdAt.toISOString(),
      totalCases: run.totalCases,
    },
    summary: {
      truePositiveRate: run.tpr,
      falsePositiveRate: run.fpr,
      precision: run.precision,
      recall: run.recall,
      score: run.score,
    },
    classification,
    cases: run.cases.map((c) => ({
      cwe: c.cweId,
      category: c.category,
      expected: c.expected,
      detected: c.detected,
      correct: c.correct,
    })),
  };

  const safeName = `${run.source}-${run.name}`.replace(/[^a-z0-9-_]+/gi, "_").slice(0, 60);

  if (format === "csv") {
    const header = "standard,run,executedAt,category,cwe,expected,detected,correct";
    const rows = run.cases.map((c) =>
      [run.source, run.name, run.createdAt.toISOString(), c.category, c.cweId, c.expected, c.detected, c.correct]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(",")
    );
    const summaryRows = [
      "",
      `"SUMMARY"`,
      `"totalCases","${run.totalCases}"`,
      `"TPR","${pct(run.tpr)}"`,
      `"FPR","${pct(run.fpr)}"`,
      `"precision","${pct(run.precision)}"`,
      `"recall","${pct(run.recall)}"`,
      `"score","${pct(run.score)}"`,
    ];
    const csv = [header, ...rows, ...summaryRows].join("\n");
    return new NextResponse(csv, {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="evidence-${safeName}.csv"`,
      },
    });
  }

  return new NextResponse(JSON.stringify(evidence, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="evidence-${safeName}.json"`,
    },
  });
}

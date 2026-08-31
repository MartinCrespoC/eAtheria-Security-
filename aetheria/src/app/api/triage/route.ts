import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { triageFindings, type TriageInput } from "@/lib/methodology";

/**
 * GET /api/triage
 * List triage results for the company
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const verdict = searchParams.get("verdict");
    const take = Math.min(parseInt(searchParams.get("take") || "50", 10), 200);

    const where: Record<string, unknown> = { companyId: session.user.companyId };
    if (verdict && ["confirmed", "not_actionable", "needs_review"].includes(verdict)) {
      where.verdict = verdict;
    }

    const results = await prisma.triageResult.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take,
    });

    return NextResponse.json(results);
  } catch (error) {
    console.error("Error fetching triage results:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

/**
 * POST /api/triage
 * Accept external findings (SARIF/CVE/GHSA/freeform) and return verdicts
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await request.json();
    const { findings, repoContext } = body as {
      findings?: TriageInput[];
      repoContext?: string;
    };

    if (!Array.isArray(findings) || findings.length === 0) {
      return NextResponse.json(
        { error: "Se requiere un array de findings" },
        { status: 400 }
      );
    }

    if (findings.length > 50) {
      return NextResponse.json(
        { error: "Máximo 50 findings por solicitud" },
        { status: 400 }
      );
    }

    // Validate each finding has minimum required fields
    for (const f of findings) {
      if (!f.title || !f.sourceType) {
        return NextResponse.json(
          { error: "Cada finding requiere 'title' y 'sourceType'" },
          { status: 400 }
        );
      }
      if (!["sarif", "cve", "advisory", "scanner_ticket", "bug_bounty", "freeform"].includes(f.sourceType)) {
        return NextResponse.json(
          { error: `sourceType inválido: ${f.sourceType}` },
          { status: 400 }
        );
      }
    }

    const results = await triageFindings(findings, session.user.companyId, repoContext);

    return NextResponse.json({
      total: results.length,
      results: results.map((r) => ({
        verdict: r.verdict,
        confidence: r.confidence,
        rationale: r.rationale,
        boundaryAssessment: r.boundaryAssessment,
        evidence: r.evidence,
        counterevidence: r.counterevidence,
        proofGaps: r.proofGaps,
        affectedPaths: r.affectedPaths,
        recommendedNext: r.recommendedNext,
        input: { title: r.input.title, sourceType: r.input.sourceType },
      })),
    });
  } catch (error) {
    console.error("Error in triage:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

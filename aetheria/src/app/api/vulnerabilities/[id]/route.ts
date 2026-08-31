import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { recordManualFalsePositiveCandidate } from "@/lib/knowledge/fp-feedback";

/**
 * PATCH /api/vulnerabilities/[id]
 * Update vulnerability status, assignment, false positive flag
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id } = await params;
    const body = await request.json();
    const { status, assignedTo, isFalsePositive, fpReason } = body;

    // Verify vulnerability belongs to user's company
    const vuln = await prisma.vulnerability.findFirst({
      where: {
        id,
        analysis: { appVersion: { application: { companyId: session.user.companyId } } },
      },
    });

    if (!vuln) {
      return NextResponse.json({ error: "Vulnerabilidad no encontrada" }, { status: 404 });
    }

    // Build update data
    const data: Record<string, unknown> = {};

    if (status && ["OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE"].includes(status)) {
      data.status = status;
      if (status === "RESOLVED") data.resolvedAt = new Date();
    }

    if (assignedTo !== undefined) {
      data.assignedTo = assignedTo;
    }

    if (typeof isFalsePositive === "boolean") {
      data.isFalsePositive = isFalsePositive;
      if (isFalsePositive) {
        data.fpReason = fpReason || null;
        data.status = "FALSE_POSITIVE";
      }
    }

    const updated = await prisma.vulnerability.update({
      where: { id },
      data,
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "UPDATE",
        entityType: "Vulnerability",
        entityId: id,
        newValues: data as Record<string, string | boolean | null>,
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    // FP feedback loop: when a user manually marks a finding as FP (last resort),
    // capture a *reviewable* candidate pattern (inactive) so the system learns.
    let learned: Awaited<ReturnType<typeof recordManualFalsePositiveCandidate>> | null = null;
    if (isFalsePositive === true) {
      learned = await recordManualFalsePositiveCandidate({
        cweId: updated.cweId,
        category: updated.category,
        title: updated.title,
        filePath: updated.filePath,
        codeSnippet: updated.codeSnippet,
        fpReason: typeof fpReason === "string" ? fpReason : null,
      });
    }

    return NextResponse.json({ ...updated, learnedPattern: learned });
  } catch (error) {
    console.error("Error updating vulnerability:", error);
    return NextResponse.json({ error: "Error interno del servidor" }, { status: 500 });
  }
}

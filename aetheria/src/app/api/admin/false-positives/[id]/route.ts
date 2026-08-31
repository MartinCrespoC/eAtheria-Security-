/**
 * False Positive Pattern Management API
 * PATCH /api/admin/false-positives/[id] - Update pattern
 * DELETE /api/admin/false-positives/[id] - Delete pattern
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { z } from "zod";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";
import { falsePositiveDetector } from "@/lib/analysis/false-positive-detector";

const updatePatternSchema = z.object({
  language: z.string().min(1).optional(),
  pattern: z.string().min(1).optional(),
  description: z.string().min(1).optional(),
  reason: z.string().min(1).optional(),
  context: z.string().optional(),
  cweIds: z.array(z.string()).optional(),
  examples: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await requireSystemAdmin();
    const { id } = await params;
    const body = await req.json();
    const validated = updatePatternSchema.parse(body);

    const pattern = await prisma.falsePositivePattern.update({
      where: { id },
      data: validated,
    });

    await logAudit({
      userId: session.user.id,
      action: AuditAction.RESOURCE_UPDATE,
      resourceType: "FALSE_POSITIVE_PATTERN",
      resourceId: pattern.id,
      details: {
        changes: validated,
      },
      severity: AuditSeverity.LOW,
      ipAddress: req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown",
      userAgent: req.headers.get("user-agent") || "unknown",
    });

    // Reload detector patterns
    await falsePositiveDetector.reload();

    return NextResponse.json({
      success: true,
      pattern,
      message: "Patrón actualizado exitosamente",
    });
  } catch (error: any) {
    console.error("Error updating false positive pattern:", error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: "Datos inválidos", details: error.issues },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: error.message || "Error al actualizar patrón" },
      { status: 500 }
    );
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await requireSystemAdmin();
    const { id } = await params;

    const pattern = await prisma.falsePositivePattern.delete({
      where: { id },
    });

    await logAudit({
      userId: session.user.id,
      action: AuditAction.RESOURCE_DELETE,
      resourceType: "FALSE_POSITIVE_PATTERN",
      resourceId: pattern.id,
      details: {
        language: pattern.language,
        description: pattern.description,
      },
      severity: AuditSeverity.MEDIUM,
      ipAddress: req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown",
      userAgent: req.headers.get("user-agent") || "unknown",
    });

    // Reload detector patterns
    await falsePositiveDetector.reload();

    return NextResponse.json({
      success: true,
      message: "Patrón eliminado exitosamente",
    });
  } catch (error: any) {
    console.error("Error deleting false positive pattern:", error);
    return NextResponse.json(
      { success: false, error: error.message || "Error al eliminar patrón" },
      { status: 500 }
    );
  }
}

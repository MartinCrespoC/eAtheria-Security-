/**
 * False Positives Management API
 * GET /api/admin/false-positives - List all patterns
 * POST /api/admin/false-positives - Create new pattern
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { z } from "zod";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";
import { falsePositiveDetector } from "@/lib/analysis/false-positive-detector";

const createPatternSchema = z.object({
  language: z.string().min(1),
  pattern: z.string().min(1),
  description: z.string().min(1),
  reason: z.string().min(1),
  context: z.string().optional(),
  cweIds: z.array(z.string()),
  examples: z.array(z.string()),
});

export async function GET(req: NextRequest) {
  try {
    const session = await requireSystemAdmin();

    const { searchParams } = new URL(req.url);
    const language = searchParams.get("language");
    const isActive = searchParams.get("isActive");
    const source = searchParams.get("source");

    const where: any = {};
    if (language) where.language = language;
    if (isActive !== null) where.isActive = isActive === "true";
    if (source) where.source = source;

    const patterns = await prisma.falsePositivePattern.findMany({
      where,
      orderBy: [{ language: "asc" }, { createdAt: "desc" }],
    });

    const stats = {
      total: patterns.length,
      byLanguage: patterns.reduce((acc: any, p) => {
        acc[p.language] = (acc[p.language] || 0) + 1;
        return acc;
      }, {}),
      bySource: patterns.reduce((acc: any, p) => {
        const src = p.source || "manual";
        acc[src] = (acc[src] || 0) + 1;
        return acc;
      }, {}),
      active: patterns.filter((p) => p.isActive).length,
      inactive: patterns.filter((p) => !p.isActive).length,
    };

    return NextResponse.json({
      success: true,
      patterns,
      stats,
    });
  } catch (error: any) {
    console.error("Error fetching false positives:", error);
    return NextResponse.json(
      { success: false, error: error.message || "Error al obtener patrones" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    const session = await requireSystemAdmin();
    const body = await req.json();

    const validated = createPatternSchema.parse(body);

    const pattern = await prisma.falsePositivePattern.create({
      data: {
        language: validated.language,
        pattern: validated.pattern,
        description: validated.description,
        reason: validated.reason,
        context: validated.context,
        cweIds: validated.cweIds,
        examples: validated.examples,
        isActive: true,
      },
    });

    await logAudit({
      userId: session.user.id,
      action: AuditAction.RESOURCE_CREATE,
      resourceType: "FALSE_POSITIVE_PATTERN",
      resourceId: pattern.id,
      details: {
        language: pattern.language,
        description: pattern.description,
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
      message: "Patrón creado exitosamente",
    });
  } catch (error: any) {
    console.error("Error creating false positive pattern:", error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: "Datos inválidos", details: error.issues },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: error.message || "Error al crear patrón" },
      { status: 500 }
    );
  }
}

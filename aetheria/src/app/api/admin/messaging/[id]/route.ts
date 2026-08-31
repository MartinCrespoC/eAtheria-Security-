/**
 * Admin Messaging Channel [id] API
 * PATCH /api/admin/messaging/[id] — Update channel
 * DELETE /api/admin/messaging/[id] — Delete channel
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { encrypt } from "@/lib/ai/encryption";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";

const updateChannelSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  config: z.record(z.string(), z.unknown()).optional(),
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
    const validated = updateChannelSchema.parse(body);

    const existing = await prisma.messagingChannel.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: "Canal no encontrado" }, { status: 404 });
    }

    // Encrypt new config values if provided
    let config = validated.config;
    if (config) {
      const sensitiveKeys = existing.platform === "telegram"
        ? ["botToken"]
        : ["accessToken", "appSecret"];
      config = { ...config };
      for (const key of sensitiveKeys) {
        if (config[key] && typeof config[key] === "string" && config[key] !== "••••••••") {
          config[key] = encrypt(config[key] as string);
        } else if (config[key] === "••••••••") {
          // Keep existing encrypted value
          delete config[key];
        }
      }
    }

    const channel = await prisma.messagingChannel.update({
      where: { id },
      data: {
        ...(validated.name && { name: validated.name }),
        ...(config && { config: { ...(existing.config as object), ...config } as Prisma.InputJsonValue }),
        ...(validated.isActive !== undefined && { isActive: validated.isActive }),
      },
    });

    await logAudit({
      userId: session.user.id,
      action: AuditAction.RESOURCE_UPDATE,
      resourceType: "MESSAGING_CHANNEL",
      resourceId: id,
      severity: AuditSeverity.LOW,
      details: { platform: existing.platform, changes: Object.keys(validated) },
    });

    return NextResponse.json({ success: true, channel: { ...channel, config: undefined }, message: "Canal actualizado" });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Datos inválidos", details: error.issues }, { status: 400 });
    }
    return NextResponse.json({ error: error instanceof Error ? error.message : "Error al actualizar" }, { status: 500 });
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await requireSystemAdmin();
    const { id } = await params;

    const existing = await prisma.messagingChannel.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: "Canal no encontrado" }, { status: 404 });
    }

    await prisma.messagingChannel.delete({ where: { id } });

    await logAudit({
      userId: session.user.id,
      action: AuditAction.RESOURCE_DELETE,
      resourceType: "MESSAGING_CHANNEL",
      resourceId: id,
      severity: AuditSeverity.MEDIUM,
      details: { platform: existing.platform, name: existing.name },
    });

    return NextResponse.json({ success: true, message: "Canal eliminado exitosamente" });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Error al eliminar" }, { status: 500 });
  }
}

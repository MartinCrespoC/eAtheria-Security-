/**
 * Admin Messaging Channels API
 * GET /api/admin/messaging — List all channels
 * POST /api/admin/messaging — Create a channel
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { encrypt } from "@/lib/ai/encryption";

const createChannelSchema = z.object({
  platform: z.enum(["telegram", "whatsapp", "whatsapp_web"]),
  name: z.string().min(1).max(100),
  config: z.record(z.string(), z.unknown()),
  isActive: z.boolean().optional(),
  companyId: z.string().optional(),
});

export async function GET() {
  try {
    await requireSystemAdmin();

    const channels = await prisma.messagingChannel.findMany({
      orderBy: { createdAt: "desc" },
      include: { company: { select: { name: true, slug: true } } },
    });

    // Sanitize config (don't return secrets)
    const sanitized = channels.map((ch) => ({
      ...ch,
      config: sanitizeConfig(ch.config as Record<string, unknown>),
    }));

    return NextResponse.json({ channels: sanitized });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Error al listar canales" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await req.json();
    const validated = createChannelSchema.parse(body);

    // Encrypt sensitive config values
    const encryptedConfig = encryptConfig(validated.config, validated.platform);

    const channel = await prisma.messagingChannel.create({
      data: {
        platform: validated.platform,
        name: validated.name,
        config: encryptedConfig as Prisma.InputJsonValue,
        isActive: validated.isActive ?? false,
        companyId: validated.companyId || null,
      },
    });

    return NextResponse.json({
      success: true,
      channel: { ...channel, config: sanitizeConfig(channel.config as Record<string, unknown>) },
      message: "Canal de mensajería creado exitosamente",
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Datos inválidos", details: error.issues },
        { status: 400 }
      );
    }
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Error al crear canal" },
      { status: 500 }
    );
  }
}

function encryptConfig(config: Record<string, unknown>, platform: string): Record<string, unknown> {
  const encrypted = { ...config };
  const sensitiveKeys = platform === "telegram"
    ? ["botToken"]
    : ["accessToken", "appSecret"];

  for (const key of sensitiveKeys) {
    if (encrypted[key] && typeof encrypted[key] === "string") {
      encrypted[key] = encrypt(encrypted[key] as string);
    }
  }
  return encrypted;
}

function sanitizeConfig(config: Record<string, unknown>): Record<string, unknown> {
  const sanitized = { ...config };
  const sensitiveKeys = ["botToken", "accessToken", "appSecret"];
  for (const key of sensitiveKeys) {
    if (sanitized[key]) {
      sanitized[key] = "••••••••";
    }
  }
  return sanitized;
}

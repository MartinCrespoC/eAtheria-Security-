/**
 * Admin Messaging Channel Test
 * POST /api/admin/messaging/[id]/test — Send a test message
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/ai/encryption";
import { sendMessagingNotification, type MessagingPlatform } from "@/lib/messaging";
import { SYSTEM_WA_SESSION } from "@/lib/messaging/whatsapp-web";
import { z } from "zod";

const testSchema = z.object({
  chatId: z.string().min(1),
});

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    await requireSystemAdmin();
    const { id } = await params;
    const body = await req.json();
    const { chatId } = testSchema.parse(body);

    const channel = await prisma.messagingChannel.findUnique({ where: { id } });
    if (!channel) {
      return NextResponse.json({ error: "Canal no encontrado" }, { status: 404 });
    }

    // Decrypt config for sending
    const config = channel.config as Record<string, unknown>;
    const decryptedConfig: Record<string, unknown> = { ...config };

    if (channel.platform === "telegram" && config.botToken) {
      decryptedConfig.botToken = decrypt(config.botToken as string);
    } else if (channel.platform === "whatsapp") {
      if (config.accessToken) decryptedConfig.accessToken = decrypt(config.accessToken as string);
      if (config.appSecret) decryptedConfig.appSecret = decrypt(config.appSecret as string);
    }

    const result = await sendMessagingNotification(
      channel.platform as MessagingPlatform,
      decryptedConfig,
      chatId,
      "✅ Mensaje de prueba desde EATHERIA Security Platform. ¡La integración funciona correctamente!",
      // WhatsApp Web sessions are per-company; global channels use the system one.
      channel.companyId ?? SYSTEM_WA_SESSION
    );

    if (!result.success) {
      return NextResponse.json(
        { success: false, error: result.error || "Error al enviar mensaje de prueba" },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `Mensaje de prueba enviado exitosamente via ${channel.platform}`,
      messageId: result.messageId,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Datos inválidos", details: error.issues }, { status: 400 });
    }
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Error al enviar prueba" },
      { status: 500 }
    );
  }
}

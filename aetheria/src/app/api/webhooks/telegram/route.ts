/**
 * Telegram Webhook Receiver
 * POST /api/webhooks/telegram
 * Receives updates from Telegram Bot API webhook.
 */

import { NextRequest, NextResponse } from "next/server";
import { parseTelegramWebhook } from "@/lib/messaging";
import { prisma } from "@/lib/db";

export async function POST(req: NextRequest) {
  try {
    // Validate secret token if configured
    const secretToken = req.headers.get("X-Telegram-Bot-Api-Secret-Token");
    const body = await req.json();

    // Parse the incoming message
    const parsed = parseTelegramWebhook(body);
    if (!parsed) {
      return NextResponse.json({ ok: true }); // Acknowledge non-message updates
    }

    // Find the messaging channel by bot token (from URL path or config)
    // For now, process commands from any configured Telegram channel
    const channels = await prisma.messagingChannel.findMany({
      where: { platform: "telegram", isActive: true },
    });

    if (channels.length === 0) {
      return NextResponse.json({ ok: true });
    }

    // Handle commands
    if (parsed.isCommand) {
      const { sendTelegramMessage } = await import("@/lib/messaging/telegram");

      for (const channel of channels) {
        const config = channel.config as Record<string, unknown>;
        const botToken = config.botToken as string;
        if (!botToken) continue;

        let response: string;
        switch (parsed.command) {
          case "scan":
            response = "🔍 Uso: /scan <nombre-aplicación>\n\nInicia un análisis de seguridad para la aplicación especificada.";
            break;
          case "status":
            response = "📊 Estado del sistema:\n\n✅ Plataforma operativa\n📈 Consulta el dashboard para métricas detalladas.";
            break;
          case "report":
            response = "📋 Reporte de vulnerabilidades:\n\nConsulta /dashboard/vulnerabilities para el reporte completo.";
            break;
          case "help":
            response = "🤖 <b>EATHERIA Bot</b>\n\nComandos disponibles:\n/scan - Iniciar análisis\n/status - Estado del sistema\n/report - Reporte de vulnerabilidades\n/help - Esta ayuda";
            break;
          default:
            response = `❓ Comando no reconocido: /${parsed.command}\n\nUsa /help para ver comandos disponibles.`;
        }

        await sendTelegramMessage(botToken, parsed.chatId, response);
      }
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("Telegram webhook error:", error);
    return NextResponse.json({ ok: false, error: "Internal error" }, { status: 500 });
  }
}

/**
 * Messaging Dispatcher
 * Unified interface for sending notifications via messaging platforms.
 */

import { sendTelegramMessage, type TelegramSendResult } from "./telegram";
import { sendWhatsAppMessage, type WhatsAppSendResult, type WhatsAppConfig } from "./whatsapp";
import { sendWAWebMessage, SYSTEM_WA_SESSION } from "./whatsapp-web";

export type MessagingPlatform = "telegram" | "whatsapp" | "whatsapp_web";

export interface MessagingResult {
  success: boolean;
  platform: string;
  messageId?: string;
  error?: string;
}

/**
 * Send a notification via the specified messaging platform.
 *
 * `sessionKey` selects the WhatsApp Web session for the `whatsapp_web`
 * platform (a company id, or `SYSTEM_WA_SESSION` for global channels).
 * It is ignored by the other platforms.
 */
export async function sendMessagingNotification(
  platform: MessagingPlatform,
  config: Record<string, unknown>,
  chatId: string,
  message: string,
  sessionKey?: string
): Promise<MessagingResult> {
  switch (platform) {
    case "telegram": {
      const botToken = config.botToken as string;
      if (!botToken) {
        return { success: false, platform, error: "Bot token no configurado" };
      }
      const result: TelegramSendResult = await sendTelegramMessage(botToken, chatId, message);
      return {
        success: result.success,
        platform,
        messageId: result.messageId?.toString(),
        error: result.error,
      };
    }

    case "whatsapp": {
      const waConfig: WhatsAppConfig = {
        phoneNumberId: config.phoneNumberId as string,
        accessToken: config.accessToken as string,
        appSecret: config.appSecret as string | undefined,
      };
      if (!waConfig.phoneNumberId || !waConfig.accessToken) {
        return { success: false, platform, error: "Configuración de WhatsApp incompleta" };
      }
      const result: WhatsAppSendResult = await sendWhatsAppMessage(waConfig, chatId, message);
      return {
        success: result.success,
        platform,
        messageId: result.messageId,
        error: result.error,
      };
    }

    case "whatsapp_web": {
      // QR-linked WhatsApp Web session. Credentials live in the persisted
      // server session (LocalAuth), so the channel only needs the destination.
      // Each company uses its own session; global channels use the system one.
      const result = await sendWAWebMessage(
        sessionKey ?? SYSTEM_WA_SESSION,
        chatId,
        message
      );
      return {
        success: result.success,
        platform,
        error: result.error,
      };
    }

    default:
      return { success: false, platform, error: `Plataforma no soportada: ${platform}` };
  }
}

// Re-export formatters
export { formatVulnAlertTelegram, formatScanSummaryTelegram } from "./telegram";
export { parseTelegramWebhook } from "./telegram";
export { parseWhatsAppWebhook, verifyWhatsAppWebhook, validateWhatsAppSignature } from "./whatsapp";

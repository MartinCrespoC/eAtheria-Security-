/**
 * Telegram Bot API Integration
 * Uses the Telegram Bot API via fetch() — no external dependencies.
 * Reference: https://core.telegram.org/bots/api
 */

export interface TelegramSendOptions {
  parseMode?: "MarkdownV2" | "HTML" | "Markdown";
  replyMarkup?: Record<string, unknown>;
  disableNotification?: boolean;
}

export interface TelegramSendResult {
  success: boolean;
  messageId?: number;
  error?: string;
}

/**
 * Send a text message via Telegram Bot API
 */
export async function sendTelegramMessage(
  botToken: string,
  chatId: string,
  text: string,
  options?: TelegramSendOptions
): Promise<TelegramSendResult> {
  try {
    const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: options?.parseMode || "HTML",
        reply_markup: options?.replyMarkup,
        disable_notification: options?.disableNotification || false,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    const data = await response.json();

    if (!data.ok) {
      return { success: false, error: data.description || "Telegram API error" };
    }

    return { success: true, messageId: data.result?.message_id };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Error al enviar mensaje de Telegram",
    };
  }
}

/**
 * Parse an incoming Telegram webhook update
 */
export function parseTelegramWebhook(body: Record<string, unknown>): {
  chatId: string;
  userId: string;
  text: string;
  username?: string;
  isCommand: boolean;
  command?: string;
} | null {
  const message = body.message as Record<string, unknown> | undefined;
  if (!message) return null;

  const chat = message.chat as Record<string, unknown>;
  const from = message.from as Record<string, unknown>;
  const text = (message.text as string) || "";

  const isCommand = text.startsWith("/");
  const command = isCommand ? text.split(" ")[0].replace("/", "").split("@")[0] : undefined;

  return {
    chatId: String(chat.id),
    userId: String(from.id),
    text,
    username: from.username as string | undefined,
    isCommand,
    command,
  };
}

/**
 * Format a vulnerability alert for Telegram
 */
export function formatVulnAlertTelegram(title: string, severity: string, description: string): string {
  const emoji = severity === "CRITICAL" ? "🔴" : severity === "HIGH" ? "🟠" : severity === "MEDIUM" ? "🟡" : "🟢";
  return `${emoji} <b>${title}</b>\n\n<b>Severidad:</b> ${severity}\n<b>Descripción:</b> ${description}`;
}

/**
 * Format a scan summary for Telegram
 */
export function formatScanSummaryTelegram(appName: string, total: number, critical: number, high: number): string {
  return `🔍 <b>Análisis completado: ${appName}</b>\n\n📊 Total: ${total} vulnerabilidades\n🔴 Críticas: ${critical}\n🟠 Altas: ${high}\n\nConsulta el dashboard para más detalles.`;
}

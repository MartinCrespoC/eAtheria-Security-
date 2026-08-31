/**
 * Company Notifier — Unified Messaging Gateway
 *
 * Hermes-inspired dispatcher: a single service that routes security events
 * (scan lifecycle, results, report exports) to every active messaging channel
 * bound to a company (Telegram / WhatsApp).
 *
 * Design notes:
 *  - Fire-and-forget: notification failures NEVER break the scan pipeline.
 *  - Secrets are decrypted in-memory at send time; they never touch the queue/DB.
 *  - Channels with `companyId === null` are "global" (system-admin monitoring)
 *    and receive alerts for every company. Company-scoped channels only receive
 *    their own company's alerts (tenant isolation).
 */

import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/ai/encryption";
import { sendMessagingNotification, type MessagingPlatform } from "./index";
import { SYSTEM_WA_SESSION } from "./whatsapp-web";

export interface BroadcastResult {
  sent: number;
  failed: number;
  channels: number;
}

export interface ScanSummary {
  analysisId: string;
  appName: string;
  version?: string;
  scanTypes: string[];
  totalVulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  duration: number;
}

/** Decrypt only the sensitive fields of a channel config, in-memory. */
function decryptChannelConfig(platform: string, config: Record<string, unknown>): Record<string, unknown> {
  const decrypted = { ...config };
  if (platform === "telegram" && typeof config.botToken === "string") {
    decrypted.botToken = decrypt(config.botToken);
  } else if (platform === "whatsapp") {
    if (typeof config.accessToken === "string") decrypted.accessToken = decrypt(config.accessToken);
    if (typeof config.appSecret === "string") decrypted.appSecret = decrypt(config.appSecret);
  }
  return decrypted;
}

/**
 * Broadcast a message to every active messaging channel that should receive
 * alerts for the given company (company-scoped + global channels).
 */
async function broadcastToCompany(companyId: string, message: string): Promise<BroadcastResult> {
  const result: BroadcastResult = { sent: 0, failed: 0, channels: 0 };

  try {
    const channels = await prisma.messagingChannel.findMany({
      where: {
        isActive: true,
        OR: [{ companyId }, { companyId: null }],
      },
    });

    result.channels = channels.length;
    if (channels.length === 0) return result;

    await Promise.all(
      channels.map(async (ch) => {
        try {
          const rawConfig = (ch.config as Record<string, unknown>) || {};
          const chatId = typeof rawConfig.chatId === "string" ? rawConfig.chatId : "";
          if (!chatId) {
            result.failed++;
            return;
          }
          const config = decryptChannelConfig(ch.platform, rawConfig);
          const res = await sendMessagingNotification(
            ch.platform as MessagingPlatform,
            config,
            chatId,
            message,
            // WhatsApp Web sessions are per-company; global channels fall back
            // to the system session.
            ch.companyId ?? SYSTEM_WA_SESSION
          );
          if (res.success) result.sent++;
          else result.failed++;
        } catch {
          result.failed++;
        }
      })
    );
  } catch (error) {
    console.error("[company-notifier] broadcast error:", error);
  }

  return result;
}

const SEVERITY_ICON: Record<string, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🟢",
  INFO: "🔵",
};

/** Notify that a scan has started. */
export async function notifyScanStarted(
  companyId: string,
  data: { appName: string; version?: string; scanTypes: string[] }
): Promise<BroadcastResult> {
  const engines = data.scanTypes.join(", ");
  const message =
    `🚀 Análisis iniciado\n\n` +
    `📦 App: ${data.appName}${data.version ? ` (v${data.version})` : ""}\n` +
    `🛠️ Motores: ${engines}\n\n` +
    `Te avisaremos cuando termine.`;
  return broadcastToCompany(companyId, message);
}

/** Notify that a scan completed, with a severity breakdown. */
export async function notifyScanCompleted(
  companyId: string,
  data: ScanSummary
): Promise<BroadcastResult> {
  const lines = [
    `✅ Análisis completado`,
    ``,
    `📦 App: ${data.appName}${data.version ? ` (v${data.version})` : ""}`,
    `🛠️ Motores: ${data.scanTypes.join(", ")}`,
    `⏱️ Duración: ${data.duration}s`,
    ``,
    `📊 Hallazgos: ${data.totalVulns}`,
  ];

  (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).forEach((sev) => {
    const count = data[sev.toLowerCase() as "critical" | "high" | "medium" | "low" | "info"];
    if (count > 0) {
      lines.push(`${SEVERITY_ICON[sev]} ${sev}: ${count}`);
    }
  });

  if (data.critical > 0) {
    lines.push(``, `⚠️ Hay ${data.critical} hallazgo(s) CRÍTICO(s). Revisa el dashboard de inmediato.`);
  } else {
    lines.push(``, `Consulta el dashboard para más detalles.`);
  }

  return broadcastToCompany(companyId, lines.join("\n"));
}

/** Notify that a scan failed. */
export async function notifyScanFailed(
  companyId: string,
  data: { appName: string; version?: string; error: string }
): Promise<BroadcastResult> {
  const message =
    `❌ Análisis fallido\n\n` +
    `📦 App: ${data.appName}${data.version ? ` (v${data.version})` : ""}\n` +
    `🧾 Error: ${data.error}\n\n` +
    `Revisa el registro del análisis en el dashboard.`;
  return broadcastToCompany(companyId, message);
}

/** Notify that a report was exported (PDF / Excel / CSV / JSON / SARIF). */
export async function notifyReportExported(
  companyId: string,
  data: { appName: string; version?: string; format: string; exportedBy?: string }
): Promise<BroadcastResult> {
  const message =
    `📄 Reporte exportado\n\n` +
    `📦 App: ${data.appName}${data.version ? ` (v${data.version})` : ""}\n` +
    `🗂️ Formato: ${data.format.toUpperCase()}\n` +
    `${data.exportedBy ? `👤 Exportado por: ${data.exportedBy}\n` : ""}` +
    `\nRegistro de auditoría generado automáticamente.`;
  return broadcastToCompany(companyId, message);
}

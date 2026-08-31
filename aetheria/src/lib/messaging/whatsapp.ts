/**
 * WhatsApp Business Cloud API Integration
 * Uses Meta's official WhatsApp Business API — stable and maintained.
 * Reference: https://developers.facebook.com/docs/whatsapp/cloud-api
 */

import { createHmac, timingSafeEqual } from "crypto";

export interface WhatsAppConfig {
  phoneNumberId: string;
  accessToken: string;
  appSecret?: string;
  webhookVerifyToken?: string;
}

export interface WhatsAppSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

const API_VERSION = "v21.0";
const BASE_URL = `https://graph.facebook.com/${API_VERSION}`;

/**
 * Send a text message via WhatsApp Business Cloud API
 */
export async function sendWhatsAppMessage(
  config: WhatsAppConfig,
  to: string,
  text: string
): Promise<WhatsAppSendResult> {
  try {
    const response = await fetch(`${BASE_URL}/${config.phoneNumberId}/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.accessToken}`,
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "text",
        text: { body: text },
      }),
      signal: AbortSignal.timeout(10_000),
    });

    const data = await response.json();

    if (!response.ok) {
      const errorMsg = data.error?.message || `WhatsApp API error: ${response.status}`;
      return { success: false, error: errorMsg };
    }

    const messageId = data.messages?.[0]?.id;
    return { success: true, messageId };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Error al enviar mensaje de WhatsApp",
    };
  }
}

/**
 * Send a template message via WhatsApp Business Cloud API
 */
export async function sendWhatsAppTemplate(
  config: WhatsAppConfig,
  to: string,
  templateName: string,
  languageCode: string,
  components: Record<string, unknown>[]
): Promise<WhatsAppSendResult> {
  try {
    const response = await fetch(`${BASE_URL}/${config.phoneNumberId}/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.accessToken}`,
      },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to,
        type: "template",
        template: {
          name: templateName,
          language: { code: languageCode },
          components,
        },
      }),
      signal: AbortSignal.timeout(10_000),
    });

    const data = await response.json();

    if (!response.ok) {
      return { success: false, error: data.error?.message || "WhatsApp template error" };
    }

    return { success: true, messageId: data.messages?.[0]?.id };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Error al enviar template de WhatsApp",
    };
  }
}

/**
 * Verify WhatsApp webhook subscription (GET request from Meta)
 */
export function verifyWhatsAppWebhook(
  mode: string,
  token: string,
  challenge: string,
  verifyToken: string
): { valid: boolean; challenge?: string } {
  if (mode === "subscribe" && token === verifyToken) {
    return { valid: true, challenge };
  }
  return { valid: false };
}

/**
 * Validate WhatsApp webhook signature (X-Hub-Signature-256)
 */
export function validateWhatsAppSignature(
  payload: string,
  signature: string,
  appSecret: string
): boolean {
  if (!signature || !appSecret) return false;

  const expectedSignature = "sha256=" + createHmac("sha256", appSecret).update(payload).digest("hex");

  try {
    return timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  } catch {
    return false;
  }
}

/**
 * Parse incoming WhatsApp webhook message
 */
export function parseWhatsAppWebhook(body: Record<string, unknown>): {
  phoneNumberId: string;
  from: string;
  text: string;
  messageId: string;
} | null {
  const entry = (body.entry as Record<string, unknown>[])?.[0];
  if (!entry) return null;

  const changes = (entry.changes as Record<string, unknown>[])?.[0];
  if (!changes) return null;

  const value = changes.value as Record<string, unknown>;
  const messages = (value?.messages as Record<string, unknown>[]) || [];
  const message = messages[0];

  if (!message || message.type !== "text") return null;

  return {
    phoneNumberId: (value?.metadata as Record<string, unknown>)?.phone_number_id as string || "",
    from: message.from as string,
    text: (message.text as Record<string, unknown>)?.body as string || "",
    messageId: message.id as string,
  };
}

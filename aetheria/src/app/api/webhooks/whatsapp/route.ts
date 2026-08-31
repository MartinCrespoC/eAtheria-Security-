/**
 * WhatsApp Webhook Receiver
 * GET /api/webhooks/whatsapp — Webhook verification (Meta)
 * POST /api/webhooks/whatsapp — Incoming messages
 */

import { NextRequest, NextResponse } from "next/server";
import { verifyWhatsAppWebhook, validateWhatsAppSignature, parseWhatsAppWebhook } from "@/lib/messaging";
import { prisma } from "@/lib/db";

/**
 * GET — Webhook verification challenge from Meta
 */
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const mode = searchParams.get("hub.mode") || "";
  const token = searchParams.get("hub.verify_token") || "";
  const challenge = searchParams.get("hub.challenge") || "";

  // Get verify token from any active WhatsApp channel
  const channels = await prisma.messagingChannel.findMany({
    where: { platform: "whatsapp", isActive: true },
  });

  for (const channel of channels) {
    const config = channel.config as Record<string, unknown>;
    const verifyToken = config.webhookVerifyToken as string;
    if (verifyToken) {
      const result = verifyWhatsAppWebhook(mode, token, challenge, verifyToken);
      if (result.valid) {
        return new NextResponse(result.challenge, {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }
    }
  }

  return NextResponse.json({ error: "Verification failed" }, { status: 403 });
}

/**
 * POST — Receive incoming WhatsApp messages
 */
export async function POST(req: NextRequest) {
  try {
    const rawBody = await req.text();
    const signature = req.headers.get("X-Hub-Signature-256") || "";

    // Get active WhatsApp channels for signature validation
    const channels = await prisma.messagingChannel.findMany({
      where: { platform: "whatsapp", isActive: true },
    });

    if (channels.length === 0) {
      return NextResponse.json({ ok: true });
    }

    // Validate signature against any configured app secret
    let signatureValid = false;
    for (const channel of channels) {
      const config = channel.config as Record<string, unknown>;
      const appSecret = config.appSecret as string;
      if (appSecret && validateWhatsAppSignature(rawBody, signature, appSecret)) {
        signatureValid = true;
        break;
      }
    }

    if (!signatureValid && channels.some(c => (c.config as Record<string, unknown>).appSecret)) {
      return NextResponse.json({ error: "Invalid signature" }, { status: 403 });
    }

    // Parse the message
    const body = JSON.parse(rawBody);
    const parsed = parseWhatsAppWebhook(body);

    if (!parsed) {
      return NextResponse.json({ ok: true }); // Acknowledge non-message events
    }

    // Log incoming message (could trigger automated responses in the future)
    console.log(`[WhatsApp] Message from ${parsed.from}: ${parsed.text}`);

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("WhatsApp webhook error:", error);
    return NextResponse.json({ ok: false, error: "Internal error" }, { status: 500 });
  }
}

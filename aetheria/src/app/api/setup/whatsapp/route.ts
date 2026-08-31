import { NextResponse } from "next/server";
import { getPrisma } from "@/lib/infrastructure/db-adapter";
import { restartWAWeb, getWAWebState, SYSTEM_WA_SESSION } from "@/lib/messaging/whatsapp-web";

export const dynamic = "force-dynamic";

/**
 * Returns true once the initial setup wizard has been completed.
 * The WhatsApp Web setup endpoint is ONLY reachable before that point.
 */
async function isSetupComplete(): Promise<boolean> {
  try {
    const client = getPrisma();
    const config = await client.systemConfig.findUnique({
      where: { key: "setup_complete" },
    });
    return config?.value === true;
  } catch {
    return false;
  }
}

/**
 * GET /api/setup/whatsapp
 *
 * Returns the current WhatsApp Web connection state (status, QR data URL,
 * connected number). Does NOT start the client — safe to poll frequently.
 *
 * POST /api/setup/whatsapp
 *
 * Starts the WhatsApp client (opens the Baileys socket and generates the QR).
 * Called once when the user reaches the WhatsApp setup step.
 *
 * Both are only accessible during the initial setup wizard — once setup is
 * complete they return 403 (the admin endpoint takes over from then on).
 */
export async function GET() {
  if (await isSetupComplete()) {
    return NextResponse.json(
      { error: "Setup already complete — use the admin panel" },
      { status: 403 }
    );
  }
  return NextResponse.json(getWAWebState(SYSTEM_WA_SESSION));
}

export async function POST() {
  if (await isSetupComplete()) {
    return NextResponse.json(
      { error: "Setup already complete — use the admin panel" },
      { status: 403 }
    );
  }

  try {
    // Kick off the client (idempotent) and return the freshest state.
    await restartWAWeb(SYSTEM_WA_SESSION);
    return NextResponse.json(getWAWebState(SYSTEM_WA_SESSION));
  } catch (error) {
    console.error("[SETUP] WhatsApp Web error:", error);
    return NextResponse.json(
      {
        status: "error",
        qr: null,
        number: null,
        pushname: null,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

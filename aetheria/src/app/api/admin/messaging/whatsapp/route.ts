import { NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import {
  restartWAWeb,
  getWAWebState,
  logoutWAWeb,
  SYSTEM_WA_SESSION,
} from "@/lib/messaging/whatsapp-web";

export const dynamic = "force-dynamic";

/**
 * GET /api/admin/messaging/whatsapp
 *
 * Returns the current WhatsApp Web connection state (status, QR data URL,
 * connected number). Does NOT start the client — safe to poll frequently.
 * System admin only (middleware + requireSystemAdmin).
 */
export async function GET() {
  try {
    await requireSystemAdmin();
    return NextResponse.json(getWAWebState(SYSTEM_WA_SESSION));
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    console.error("[ADMIN] WhatsApp Web status error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * POST /api/admin/messaging/whatsapp
 *
 * Starts the WhatsApp client (opens the Baileys socket and generates the QR).
 * Idempotent — if a session already exists it reconnects silently.
 */
export async function POST() {
  try {
    await requireSystemAdmin();
    await restartWAWeb(SYSTEM_WA_SESSION);
    return NextResponse.json(getWAWebState(SYSTEM_WA_SESSION));
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    console.error("[ADMIN] WhatsApp Web start error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * DELETE /api/admin/messaging/whatsapp
 *
 * Logs out the current WhatsApp Web session (invalidates the linked device)
 * and resets the connection. A new QR will be required to reconnect.
 */
export async function DELETE() {
  try {
    await requireSystemAdmin();
    const state = await logoutWAWeb(SYSTEM_WA_SESSION);
    return NextResponse.json({ success: true, ...state });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    console.error("[ADMIN] WhatsApp Web logout error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

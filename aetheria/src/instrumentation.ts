/**
 * Next.js instrumentation hook — runs once when the server starts.
 *
 * Auto-restores persisted WhatsApp (Baileys) sessions after a restart so the
 * messaging gateway comes back online by itself — no new QR scan and no need to
 * open the panel or send a message first. The credentials survived the restart
 * on disk (`.baileys_auth/<session>/`); this simply re-establishes the sockets
 * from them at boot.
 *
 * The work is fire-and-forget so it never delays server startup; the panel's
 * status polling picks up the restored "ready" state within a few seconds.
 */
export async function register() {
  // Only run in the Node.js server runtime — never in the edge/middleware
  // runtime (Baileys is a pure-Node client and is externalized there).
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  const { restorePersistedSessions } = await import(
    "@/lib/messaging/whatsapp-web"
  );

  restorePersistedSessions().catch((error) => {
    console.warn("[wa] WhatsApp session auto-restore failed:", error);
  });
}

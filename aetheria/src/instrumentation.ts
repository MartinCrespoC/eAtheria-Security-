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

  // Orphaned scan cleanup: if the server restarted mid-scan, analyses left in
  // PENDING/INITIALIZING/SCANNING/VALIDATING/ENRICHING would hang forever (the trigger function lived
  // only in the old process memory). Mark them FAILED so the user gets a clear
  // terminal state instead of a spinner that never resolves.
  const { prisma } = await import("@/lib/db");
  prisma.analysis
    .updateMany({
      where: { status: { in: ["PENDING", "INITIALIZING", "SCANNING", "VALIDATING", "ENRICHING"] } },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage:
          "Server restarted mid-scan — the in-memory scan worker was lost. Re-run the scan.",
      },
    })
    .then(({ count }) => {
      if (count > 0)
        console.warn(`[scan-recovery] Marked ${count} orphaned scan(s) as FAILED after restart`);
    })
    .catch((error) => {
      console.warn("[scan-recovery] Orphaned scan cleanup failed:", error);
    });
}

/**
 * WhatsApp Gateway (Baileys) — Multi-tenant
 *
 * QR-code based WhatsApp connection — the "easy setup" alternative to the
 * official Meta Cloud API. Works like WhatsApp Web: the server generates a QR
 * code, the user scans it with their phone (Linked Devices), and a persistent
 * session is established.
 *
 * This gateway is built on Baileys (`@whiskeysockets/baileys`), a pure-Node
 * implementation of the WhatsApp Web protocol. Unlike the previous
 * whatsapp-web.js implementation it does NOT run a headless Chromium — the
 * "session" is just a small folder of encryption keys + device credentials.
 *
 * Multi-tenancy:
 *  - Each company gets its OWN session, keyed by its `companyId`.
 *  - The setup wizard and the system-admin global panel use the reserved
 *    `SYSTEM_WA_SESSION` key (preserving the original single-session behavior).
 *
 * Architecture notes:
 *  - Every session is a long-lived Baileys socket stored in a `globalThis`
 *    registry that survives Next.js route-handler invocations and dev
 *    hot-reloads.
 *  - Session persistence uses `useMultiFileAuthState`, storing each linked
 *    device's credentials under `.baileys_auth/<sessionKey>`. Credentials are
 *    written to disk on every `creds.update`, so after the first successful
 *    scan the session survives restarts — even abrupt process kills — and
 *    reconnects WITHOUT a new QR.
 *  - Resilience: dropped connections auto-reconnect with exponential backoff
 *    (using the persisted credentials, no new QR), and message sends lazily
 *    re-establish a dead session before giving up. Only an invalidated session
 *    (logged out on the phone) requires a fresh QR scan.
 *  - Baileys sessions are lightweight (no browser), so the concurrent-session
 *    cap (`MAX_CONCURRENT_WA_SESSIONS`, default 5) is now just a safety valve.
 *  - The Baileys module is imported lazily so it is only loaded when WhatsApp
 *    is actually used.
 *
 * ⚠️ This uses the unofficial WhatsApp Web protocol. It is intended for
 *    low-volume operational notifications, not bulk marketing.
 */

import { join } from "path";
import { readdir, readFile, rm } from "fs/promises";
import QRCode from "qrcode";
import type { Boom } from "@hapi/boom";
import type { WASocket } from "@whiskeysockets/baileys";

/** Reserved session key for the setup wizard + system-admin global panel. */
export const SYSTEM_WA_SESSION = "__system__";

/** Max concurrent WhatsApp sessions (safety valve — sessions are lightweight). */
const MAX_CONCURRENT_WA_SESSIONS = parseInt(
  process.env.MAX_CONCURRENT_WA_SESSIONS ?? "5",
  10
);

/** Base delay for the exponential backoff used by the auto-reconnect. */
const RECONNECT_BASE_DELAY_MS = 5_000;
/** Upper bound for the delay between auto-reconnect attempts. */
const RECONNECT_MAX_DELAY_MS = 5 * 60_000;
/** How long a message send waits for a lazily re-established session. */
const SEND_RECONNECT_TIMEOUT_MS = 30_000;

/** Base directory holding one auth folder per session (device credentials). */
const BAILEYS_AUTH_DIR = process.env.BAILEYS_AUTH_DIR ?? ".baileys_auth";

export type WAWebStatus =
  | "idle" // No socket created yet
  | "initializing" // Socket created, restoring session / connecting
  | "waiting_qr" // QR available, waiting for the user to scan
  | "authenticated" // QR scanned, session being restored
  | "ready" // Connected and able to send messages
  | "disconnected" // Connection lost / logged out
  | "error"; // Fatal error (cap reached, init failure, ...)

export interface WAWebState {
  status: WAWebStatus;
  /** QR code as a data URL (only present while status === "waiting_qr"). */
  qr: string | null;
  /** Connected phone number (digits only), once ready. */
  number: string | null;
  /** WhatsApp profile name of the connected account, once ready. */
  pushname: string | null;
  error: string | null;
}

interface WAWebEntry {
  sock?: WASocket;
  state: WAWebState;
  saveCreds?: () => Promise<void>;
  starting?: boolean;
  /** Set when the user explicitly logs out — suppresses auto-reconnect. */
  manualLogout?: boolean;
  /** Pending auto-reconnect timer (exponential backoff). */
  reconnectTimer?: ReturnType<typeof setTimeout>;
  /** Consecutive reconnect attempts since the last healthy connection. */
  reconnectAttempts?: number;
}

interface WAWebGlobal {
  registry?: Map<string, WAWebEntry>;
}

const g = globalThis as unknown as { __aetheriaWaWeb?: WAWebGlobal };

function getGlobal(): WAWebGlobal {
  if (!g.__aetheriaWaWeb) g.__aetheriaWaWeb = {};
  return g.__aetheriaWaWeb;
}

function getRegistry(): Map<string, WAWebEntry> {
  const gw = getGlobal();
  if (!gw.registry) gw.registry = new Map();
  return gw.registry;
}

function freshState(): WAWebState {
  return {
    status: "idle",
    qr: null,
    number: null,
    pushname: null,
    error: null,
  };
}

function getEntry(sessionKey: string): WAWebEntry {
  const registry = getRegistry();
  let entry = registry.get(sessionKey);
  if (!entry) {
    entry = { state: freshState() };
    registry.set(sessionKey, entry);
  }
  return entry;
}

/** Count sessions that currently occupy a slot (live socket or starting). */
function countLiveSessions(): number {
  let count = 0;
  for (const entry of getRegistry().values()) {
    if (entry.sock || entry.starting) count++;
  }
  return count;
}

/** Auth folder for a session (device credentials — never commit). */
function authFolder(sessionKey: string): string {
  // turbopackIgnore: the session key is dynamic, but this only ever resolves
  // inside BAILEYS_AUTH_DIR — tell Turbopack's file tracer not to flag it.
  return join(/*turbopackIgnore: true*/ BAILEYS_AUTH_DIR, sessionKey);
}

/** Extract the bare phone number (digits) from a Baileys JID. */
function parseNumber(jid?: string): string | null {
  if (!jid) return null;
  // "34600000000:12@s.whatsapp.net" -> "34600000000"
  return jid.split("@")[0]?.split(":")[0] ?? null;
}

/**
 * Minimal logger matching Baileys' ILogger shape. Keeps the server log clean
 * by silencing trace/debug/info and forwarding only warnings and errors.
 */
type BaileysLogger = {
  level: string;
  child(obj: Record<string, unknown>): BaileysLogger;
  trace(obj: unknown, msg?: string): void;
  debug(obj: unknown, msg?: string): void;
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
};

const baileysLogger: BaileysLogger = {
  level: "warn",
  child: () => baileysLogger,
  trace: () => {},
  debug: () => {},
  info: () => {},
  warn: (obj, msg) => console.warn("[baileys]", msg ?? obj),
  error: (obj, msg) => console.error("[baileys]", msg ?? obj),
};

/** Return a snapshot of the current connection state for a session key. */
export function getWAWebState(sessionKey: string): WAWebState {
  return { ...getEntry(sessionKey).state };
}

/**
 * Ensure a WhatsApp socket exists for the given session key and is
 * connecting/connected. Idempotent — safe to call on every status/QR request.
 * Enforces the concurrent-session cap before opening a new socket.
 */
export async function ensureWAWebClient(sessionKey: string): Promise<WAWebState> {
  const entry = getEntry(sessionKey);
  const { state } = entry;

  if (entry.sock || entry.starting) return { ...state };

  // Explicit connect intent — re-enable auto-reconnect and cancel any pending
  // backoff timer (we are about to connect synchronously).
  entry.manualLogout = false;
  if (entry.reconnectTimer) {
    clearTimeout(entry.reconnectTimer);
    entry.reconnectTimer = undefined;
  }

  // Enforce the concurrent-session cap before opening a new socket.
  if (countLiveSessions() >= MAX_CONCURRENT_WA_SESSIONS) {
    state.status = "error";
    state.error = `Límite de sesiones de WhatsApp alcanzado (máx. ${MAX_CONCURRENT_WA_SESSIONS}). Desconecta otra empresa e inténtalo de nuevo.`;
    state.qr = null;
    return { ...state };
  }

  entry.starting = true;
  state.status = "initializing";
  state.error = null;
  state.qr = null;

  try {
    // Lazy import: keeps Baileys off the cold path. `useMultiFileAuthState`
    // is renamed to avoid the react-hooks "use*" lint rule (it is not a hook).
    const {
      makeWASocket,
      useMultiFileAuthState: loadMultiFileAuthState,
      fetchLatestWaWebVersion,
      DisconnectReason,
    } = await import("@whiskeysockets/baileys");

    // Baileys ships a hardcoded WA Web version that goes stale — WhatsApp then
    // closes fresh sockets before issuing a QR (the "Could not start" symptom).
    // Always negotiate the current version; fall back to the bundled default
    // only if the fetch fails (offline).
    let version: [number, number, number] | undefined;
    try {
      version = (await fetchLatestWaWebVersion({})).version;
    } catch {
      version = undefined;
    }

    // Per-session credentials folder => one persisted session per company.
    // loadMultiFileAuthState reads any existing creds (restart => no new QR).
    const { state: authState, saveCreds } = await loadMultiFileAuthState(
      authFolder(sessionKey)
    );
    entry.saveCreds = saveCreds;

    const sock = makeWASocket({
      auth: authState,
      version,
      printQRInTerminal: false,
      markOnlineOnConnect: true,
      syncFullHistory: false,
      // Explicit browser identity — without it, freshly-paired sessions get
      // rejected right after the QR scan (QR disappears, never connects).
      browser: ["Ubuntu", "Chrome", "126.0.0.0"],
      logger: baileysLogger,
    });

    entry.sock = sock;

    // Persist credentials on EVERY update — this is what makes the session
    // survive restarts (and abrupt kills) without a new QR.
    sock.ev.on("creds.update", async () => {
      await saveCreds();
      // Clean post-scan transition: once the device is registered, move from
      // waiting_qr/initializing to authenticated (then "open" -> ready).
      if (
        sock.authState.creds.registered &&
        (state.status === "waiting_qr" || state.status === "initializing")
      ) {
        state.status = "authenticated";
        state.qr = null;
      }
    });

    sock.ev.on("connection.update", async ({ connection, lastDisconnect, qr }) => {
      // A (regenerated) QR is available — render it for the panel.
      if (qr) {
        state.status = "waiting_qr";
        try {
          state.qr = await QRCode.toDataURL(qr, { margin: 1, width: 260 });
        } catch {
          state.qr = null;
        }
      }

      if (connection === "open") {
        state.status = "ready";
        state.qr = null;
        state.error = null;
        state.number = parseNumber(sock.user?.id);
        state.pushname = sock.user?.name ?? null;
        // Healthy connection — reset the auto-reconnect backoff.
        entry.reconnectAttempts = 0;
        entry.manualLogout = false;
      }

      if (connection === "close") {
        const statusCode = (lastDisconnect?.error as Boom)?.output?.statusCode;
        const loggedOut = statusCode === DisconnectReason.loggedOut;
        // restartRequired (515) is the NORMAL close right after a QR scan —
        // WhatsApp expects an immediate reconnect with the just-paired creds.
        const restartRequired =
          statusCode === DisconnectReason.restartRequired;
        console.warn(
          `[whatsapp-web] connection closed for ${sessionKey} (statusCode=${statusCode}, loggedOut=${loggedOut})`
        );
        // Free the socket slot either way.
        entry.sock = undefined;

        if (loggedOut) {
          // The linked device was invalidated on the phone — the stored creds
          // are useless now. Delete them so the next connect issues a fresh QR
          // instead of looping on the dead session.
          state.status = "disconnected";
          state.error = "Sesión cerrada — vuelve a escanear el QR";
          state.qr = null;
          await rm(authFolder(sessionKey), { recursive: true, force: true }).catch(
            () => {}
          );
        } else if (restartRequired) {
          // Immediate reconnect — no backoff. This is the post-scan handshake.
          state.status = "initializing";
          state.qr = null;
          void ensureWAWebClient(sessionKey);
        } else {
          // Transient drop — re-establish from the persisted creds (no new QR).
          state.status = "disconnected";
          state.qr = null;
          scheduleReconnect(sessionKey, entry);
        }
      }
    });
  } catch (error) {
    state.status = "error";
    state.error =
      error instanceof Error ? error.message : "No se pudo inicializar WhatsApp";
    state.qr = null;
    entry.sock = undefined;
  } finally {
    entry.starting = false;
  }

  return { ...state };
}

/**
 * Schedule an auto-reconnect attempt using exponential backoff. Because the
 * credentials are persisted by useMultiFileAuthState, a reconnect does NOT
 * require a new QR — unless the linked device was invalidated on the phone, in
 * which case the socket emits a QR and waits for a human scan.
 */
function scheduleReconnect(sessionKey: string, entry: WAWebEntry): void {
  if (entry.manualLogout) return;
  if (entry.reconnectTimer) return; // already scheduled

  const attempts = entry.reconnectAttempts ?? 0;
  const delay = Math.min(
    RECONNECT_BASE_DELAY_MS * Math.pow(2, attempts),
    RECONNECT_MAX_DELAY_MS
  );

  entry.reconnectTimer = setTimeout(async () => {
    entry.reconnectTimer = undefined;
    entry.reconnectAttempts = attempts + 1;
    // Bail out if the session recovered on its own or the user logged out.
    if (entry.manualLogout || entry.sock || entry.starting) return;
    await ensureWAWebClient(sessionKey);
  }, delay);
}

/** Wait up to `timeoutMs` for a session to reach the "ready" state. */
async function waitForReady(
  sessionKey: string,
  timeoutMs: number
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { state, sock } = getEntry(sessionKey);
    if (sock && state.status === "ready") return true;
    // Terminal states that will not self-heal — stop waiting early.
    if (state.status === "waiting_qr" || state.status === "error") return false;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

/**
 * Send a text message through the connected WhatsApp session for the given
 * session key. `to` may be a bare number ("34600000000") or a full JID.
 */
export async function sendWAWebMessage(
  sessionKey: string,
  to: string,
  text: string
): Promise<{ success: boolean; error?: string }> {
  let entry = getEntry(sessionKey);

  // Self-healing: if the session is not ready (server restart, dropped
  // connection, ...) re-establish it from the persisted credentials — no new
  // QR — and wait briefly for it to come up before giving up. Skipped when the
  // user explicitly logged out.
  if ((!entry.sock || entry.state.status !== "ready") && !entry.manualLogout) {
    await ensureWAWebClient(sessionKey);
    await waitForReady(sessionKey, SEND_RECONNECT_TIMEOUT_MS);
    entry = getEntry(sessionKey);
  }

  if (!entry.sock || entry.state.status !== "ready") {
    return {
      success: false,
      error:
        entry.state.status === "waiting_qr"
          ? "La sesión de WhatsApp expiró — vuelve a escanear el QR"
          : "WhatsApp no está conectado",
    };
  }

  try {
    const jid = to.includes("@") ? to : `${to.replace(/\D/g, "")}@s.whatsapp.net`;
    await entry.sock.sendMessage(jid, { text });
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error:
        error instanceof Error ? error.message : "Error al enviar el mensaje",
    };
  }
}

/**
 * Force-restart the session: tears down any stale/half-open socket and opens a
 * fresh one from the persisted credentials (no new QR unless logged out).
 *
 * This is what the panel's "Conectar" button must call — `ensureWAWebClient`
 * is idempotent and returns early when a stale `sock`/`starting` is present,
 * which made the button a no-op in exactly the states where it was needed.
 */
export async function restartWAWeb(sessionKey: string): Promise<WAWebState> {
  const entry = getEntry(sessionKey);

  // Cancel any pending backoff retry — we are reconnecting NOW.
  if (entry.reconnectTimer) {
    clearTimeout(entry.reconnectTimer);
    entry.reconnectTimer = undefined;
  }
  entry.manualLogout = false;

  // Tear down whatever socket object exists (may be half-open or dead).
  if (entry.sock) {
    try {
      entry.sock.ev.removeAllListeners("connection.update");
      entry.sock.ev.removeAllListeners("creds.update");
    } catch {
      /* ignore */
    }
    try {
      entry.sock.end(undefined);
    } catch {
      /* ignore close errors */
    }
    entry.sock = undefined;
  }
  entry.starting = false;

  return ensureWAWebClient(sessionKey);
}

/**
 * Log out the session for the given key (invalidates the linked device), reset
 * its state, and free the concurrent-session slot. A new QR will be required
 * to reconnect.
 */
export async function logoutWAWeb(sessionKey: string): Promise<WAWebState> {
  const entry = getEntry(sessionKey);

  // Intentional logout — suppress auto-reconnect and cancel pending retries.
  entry.manualLogout = true;
  if (entry.reconnectTimer) {
    clearTimeout(entry.reconnectTimer);
    entry.reconnectTimer = undefined;
  }
  entry.reconnectAttempts = 0;

  if (entry.sock) {
    try {
      await entry.sock.logout();
    } catch {
      /* ignore logout errors */
    }
    try {
      await entry.sock.end(undefined);
    } catch {
      /* ignore close errors */
    }
    entry.sock = undefined;
  }

  // Delete the persisted credentials so a fresh QR is required to reconnect.
  await rm(authFolder(sessionKey), { recursive: true, force: true }).catch(() => {});

  // Reset in place to keep the shared state reference stable.
  Object.assign(entry.state, freshState());

  return { ...entry.state };
}

/**
 * Restore previously-paired sessions after a server restart.
 *
 * Scans `BAILEYS_AUTH_DIR` for session folders whose persisted credentials are
 * paired (`creds.me` present) and re-establishes each socket from disk — no new
 * QR. Invoked once at boot from `instrumentation.ts` so the gateway comes back
 * online automatically instead of waiting for someone to open the panel.
 *
 * Sessions are restored sequentially so the concurrent-session cap is honoured;
 * anything beyond the cap reconnects lazily on first send. Folders without a
 * paired identity (half-started pairings) are skipped so we never spawn a socket
 * that would just emit a QR at boot.
 */
export async function restorePersistedSessions(): Promise<void> {
  let sessionKeys: string[];
  try {
    sessionKeys = await readdir(BAILEYS_AUTH_DIR);
  } catch {
    return; // no auth dir yet — nothing to restore
  }

  for (const sessionKey of sessionKeys) {
    // Only restore sessions that were actually paired (have a device identity).
    // Reading creds.json also naturally skips non-directory entries and
    // half-started pairings, so we never spawn a socket that would emit a QR.
    try {
      const raw = await readFile(join(authFolder(sessionKey), "creds.json"), "utf8");
      const creds = JSON.parse(raw) as { me?: unknown };
      if (!creds.me) continue;
    } catch {
      continue; // not a session folder / unreadable / invalid creds — skip
    }

    try {
      const state = await ensureWAWebClient(sessionKey);
      if (state.status === "error") {
        // Most likely the concurrent-session cap — stop trying further sessions.
        console.warn(`[wa] auto-restore skipped "${sessionKey}": ${state.error}`);
        break;
      }
      console.log(`[wa] auto-restoring persisted session "${sessionKey}" (${state.status})`);
    } catch (error) {
      console.warn(`[wa] could not auto-restore "${sessionKey}":`, error);
    }
  }
}

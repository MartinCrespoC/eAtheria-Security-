"use client";

/**
 * WhatsAppWebPanel — QR-code connection UI for WhatsApp (Baileys gateway).
 *
 * Shows the live connection status and the scannable QR code. The session is
 * persisted server-side (Baileys auth folder), so the QR is only needed the
 * first time (or after a logout); restarts reconnect automatically.
 */

import { useCallback, useEffect, useState } from "react";
import {
  QrCode,
  Smartphone,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  PlugZap,
  Power,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface WAWebState {
  status:
    | "idle"
    | "initializing"
    | "waiting_qr"
    | "authenticated"
    | "ready"
    | "disconnected"
    | "error";
  qr: string | null;
  number: string | null;
  pushname: string | null;
  error: string | null;
}

const STATUS_META: Record<
  WAWebState["status"],
  { label: string; className: string }
> = {
  idle: { label: "Sin conectar", className: "bg-slate-500/20 text-slate-400" },
  initializing: { label: "Inicializando…", className: "bg-cyan-500/20 text-cyan-400" },
  waiting_qr: { label: "Esperando escaneo", className: "bg-amber-500/20 text-amber-400" },
  authenticated: { label: "Autenticando…", className: "bg-cyan-500/20 text-cyan-400" },
  ready: { label: "Conectado", className: "bg-green-500/20 text-green-400" },
  disconnected: { label: "Desconectado", className: "bg-red-500/20 text-red-400" },
  error: { label: "Error", className: "bg-red-500/20 text-red-400" },
};

export function WhatsAppWebPanel({
  apiBase = "/api/admin/messaging/whatsapp",
}: {
  /** Base endpoint for the WhatsApp Web session API (system admin by default). */
  apiBase?: string;
}) {
  const [state, setState] = useState<WAWebState | null>(null);
  const [busy, setBusy] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(apiBase);
      if (res.ok) setState(await res.json());
    } catch {
      /* ignore polling errors */
    }
  }, [apiBase]);

  // Poll status so the QR / connection state stays live.
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  async function handleConnect() {
    setBusy(true);
    try {
      const res = await fetch(apiBase, { method: "POST" });
      if (res.ok) setState(await res.json());
    } catch {
      /* ignore */
    } finally {
      setBusy(false);
    }
  }

  async function handleDisconnect() {
    if (!confirm("¿Cerrar la sesión de WhatsApp Web? Necesitarás escanear un nuevo QR para reconectar.")) return;
    setBusy(true);
    try {
      const res = await fetch(apiBase, { method: "DELETE" });
      if (res.ok) setState(await res.json());
    } catch {
      /* ignore */
    } finally {
      setBusy(false);
    }
  }

  const status = state?.status ?? "idle";
  const meta = STATUS_META[status];

  return (
    <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="h-9 w-9 rounded-lg bg-green-500/15 border border-green-500/30 flex items-center justify-center">
            <Smartphone className="h-4.5 w-4.5 text-green-400" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-white">WhatsApp Web (QR)</h3>
            <p className="text-xs text-slate-500">
              Conexión por código QR — sesión persistente, sin cuenta Business
            </p>
          </div>
        </div>
        <span className={cn("px-2.5 py-1 rounded-full text-xs font-semibold", meta.className)}>
          {meta.label}
        </span>
      </div>

      {/* QR / status body */}
      <div className="flex flex-col sm:flex-row items-center gap-5">
        {status === "waiting_qr" && state?.qr ? (
          <div className="flex flex-col items-center gap-2">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={state.qr}
              alt="Código QR de WhatsApp"
              className="w-44 h-44 rounded-lg bg-white p-2 border border-slate-700"
            />
            <p className="text-xs text-slate-400 text-center max-w-[200px]">
              Abre WhatsApp → Ajustes → <span className="text-slate-200">Dispositivos vinculados</span> → escanea este QR
            </p>
          </div>
        ) : status === "ready" ? (
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-8 w-8 text-green-400" />
            <div>
              <p className="text-sm font-semibold text-white">
                {state?.pushname || "Cuenta conectada"}
              </p>
              <p className="text-xs text-slate-400 font-mono">+{state?.number}</p>
            </div>
          </div>
        ) : status === "initializing" || status === "authenticated" ? (
          <div className="flex items-center gap-3 text-cyan-400">
            <Loader2 className="h-6 w-6 animate-spin" />
            <p className="text-sm">
              {status === "initializing" ? "Lanzando WhatsApp Web…" : "Restaurando sesión…"}
            </p>
          </div>
        ) : status === "error" ? (
          <div className="flex items-center gap-3 text-red-400">
            <AlertTriangle className="h-6 w-6" />
            <p className="text-sm">{state?.error || "Error desconocido"}</p>
          </div>
        ) : (
          <div className="flex items-center gap-3 text-slate-400">
            <QrCode className="h-6 w-6" />
            <p className="text-sm">
              {status === "disconnected"
                ? "Sesión finalizada. Conecta de nuevo para generar un QR."
                : "Conecta WhatsApp para enviar alertas de escaneo por esta vía."}
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="sm:ml-auto flex items-center gap-2">
          {status !== "ready" && (
            <button
              onClick={handleConnect}
              disabled={busy || status === "initializing" || status === "authenticated"}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white text-sm font-medium transition-colors"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlugZap className="h-4 w-4" />}
              {status === "waiting_qr" ? "Regenerar QR" : "Conectar"}
            </button>
          )}
          {(status === "ready" || status === "waiting_qr") && (
            <button
              onClick={handleDisconnect}
              disabled={busy}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white text-sm font-medium transition-colors"
            >
              <Power className="h-4 w-4" />
              Desconectar
            </button>
          )}
        </div>
      </div>

      <p className="mt-4 text-[11px] text-slate-500">
        ⚠️ Usa el protocolo no oficial de WhatsApp Web. Recomendado para notificaciones
        operativas de bajo volumen; la sesión se restaura automáticamente tras reinicios.
      </p>
    </div>
  );
}

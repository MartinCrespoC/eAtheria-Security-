"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  MessageSquare,
  QrCode,
  Loader2,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Smartphone,
} from "lucide-react";
import { cn } from "@/lib/utils";

type WAStatus =
  | "idle"
  | "initializing"
  | "waiting_qr"
  | "authenticated"
  | "ready"
  | "disconnected"
  | "error";

interface WAState {
  status: WAStatus;
  qr: string | null;
  number: string | null;
  pushname: string | null;
  error: string | null;
}

export default function WhatsAppSetupPage() {
  const router = useRouter();
  const [state, setState] = useState<WAState | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/setup/whatsapp");
      if (res.ok) setState(await res.json());
    } catch {
      /* ignore polling errors */
    }
  }, []);

  // Start the WhatsApp Web client once, then poll for the live QR / status.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/setup/whatsapp", { method: "POST" });
        if (res.ok && !cancelled) setState(await res.json());
      } catch {
        /* ignore */
      }
    })();
    const interval = setInterval(fetchStatus, 2500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [fetchStatus]);

  const status: WAStatus = state?.status ?? "initializing";

  return (
    <div>
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-green-500/10 border border-green-500/30 mb-3">
          <MessageSquare className="w-7 h-7 text-green-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-1">
          Connect WhatsApp <span className="text-green-400">(optional)</span>
        </h2>
        <p className="text-sm text-slate-400">
          Link a WhatsApp number via QR to receive scan alerts and report
          notifications. You can skip this and configure it later in the admin
          panel.
        </p>
      </div>

      {/* QR / status area */}
      <div className="flex flex-col items-center gap-4 py-4">
        {status === "waiting_qr" && state?.qr ? (
          <>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={state.qr}
              alt="WhatsApp QR code"
              className="w-52 h-52 rounded-xl bg-white p-3 border border-slate-700 shadow-lg shadow-green-500/10"
            />
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Smartphone className="w-4 h-4 text-green-400" />
              <span>
                WhatsApp → Settings → <span className="text-white">Linked devices</span> → scan QR
              </span>
            </div>
          </>
        ) : status === "ready" ? (
          <div className="flex flex-col items-center gap-2">
            <CheckCircle2 className="w-14 h-14 text-green-400" />
            <p className="text-sm font-semibold text-white">
              {state?.pushname || "Connected"}
            </p>
            <p className="text-xs text-slate-400 font-mono">+{state?.number}</p>
            <p className="text-xs text-green-400">
              WhatsApp linked — scan alerts will be delivered to this number.
            </p>
          </div>
        ) : status === "error" || status === "disconnected" ? (
          <div className="flex flex-col items-center gap-2 text-center">
            <AlertTriangle className="w-10 h-10 text-amber-400" />
            <p className="text-sm text-slate-300">
              {state?.error || "Could not start WhatsApp Web."}
            </p>
            <p className="text-xs text-slate-500 max-w-sm">
              You can skip this step and connect WhatsApp later from{" "}
              <span className="font-mono text-slate-400">Admin → Messaging</span>.
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3 py-6">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
            <p className="text-sm text-slate-400">
              {status === "initializing"
                ? "Launching WhatsApp Web…"
                : "Restoring session…"}
            </p>
          </div>
        )}
      </div>

      {/* Info note */}
      <div className="mt-2 p-3 rounded-lg border border-slate-700/50 bg-slate-900/40">
        <p className="text-xs text-slate-400 flex items-start gap-2">
          <QrCode className="w-4 h-4 flex-shrink-0 mt-0.5 text-green-400" />
          The session is stored on the server and restored automatically after
          restarts — you only need to scan the QR once. This uses the unofficial
          WhatsApp Web protocol, best for low-volume operational alerts.
        </p>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between mt-6">
        <Button variant="ghost" onClick={() => router.push("/setup/ai")}>
          <ArrowLeft className="w-4 h-4" />
          Back
        </Button>

        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={() => router.push("/setup/complete")}>
            Skip
          </Button>
          <Button
            onClick={() => router.push("/setup/complete")}
            disabled={status !== "ready"}
            className={cn(status === "ready" && "bg-green-600 hover:bg-green-500")}
          >
            {status === "ready" ? "Continue" : "Waiting for scan…"}
            <ArrowRight className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

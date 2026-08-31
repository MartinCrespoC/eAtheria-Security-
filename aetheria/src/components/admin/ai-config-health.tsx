"use client";

import { useEffect, useState, useCallback } from "react";
import { Loader2, HeartPulse, Activity, RefreshCw, Zap } from "lucide-react";

interface HealthEntry {
  id: string;
  status: string;
  latencyMs: number;
  error: string | null;
  checkedAt: string;
}

interface ProviderHealthData {
  id: string;
  name: string;
  slug: string;
  type: string;
  isActive: boolean;
  health: {
    status: string;
    latencyMs: number;
    error: string | null;
    lastCheckedAt: string | null;
  };
}

interface ProviderHealthDetail {
  provider: { id: string; name: string; slug: string } | null;
  status: {
    providerId: string;
    status: string;
    latencyMs: number;
    error: string | null;
    lastCheckedAt: string | null;
  };
  uptime: number;
  history: HealthEntry[];
}

const STATUS_COLORS: Record<string, string> = {
  healthy: "#00ff88",
  degraded: "#ffaa00",
  down: "#ff4444",
};

const STATUS_LABELS: Record<string, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  down: "Down",
};

export function AIConfigHealth() {
  const [providers, setProviders] = useState<ProviderHealthData[]>([]);
  const [loading, setLoading] = useState(true);
  const [checkingAll, setCheckingAll] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState<ProviderHealthDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchSummary = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-configuration/health");
      if (res.ok) {
        setProviders(await res.json());
      }
    } catch {
      showMsg("error", "Failed to load health data");
    } finally {
      setLoading(false);
    }
  }, [showMsg]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  async function runAllChecks() {
    setCheckingAll(true);
    try {
      const res = await fetch("/api/admin/ai-configuration/health", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        showMsg("success", `Checked ${data.total} providers: ${data.healthy} healthy, ${data.degraded} degraded, ${data.down} down`);
        await fetchSummary();
      }
    } catch {
      showMsg("error", "Health check failed");
    }
    setCheckingAll(false);
  }

  async function fetchDetail(providerId: string) {
    setDetailLoading(true);
    try {
      const res = await fetch(`/api/admin/ai-configuration/health?providerId=${providerId}&hours=24`);
      if (res.ok) {
        setSelectedDetail(await res.json());
      }
    } catch {
      showMsg("error", "Failed to load detail");
    }
    setDetailLoading(false);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {message && (
        <div
          className={`rounded-lg px-4 py-3 text-sm font-medium ${
            message.type === "success"
              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border border-red-500/30 text-red-400"
          }`}
        >
          {message.text}
        </div>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <HeartPulse className="h-5 w-5 text-cyan-400" />
          Health Dashboard
        </h2>
        <button
          onClick={runAllChecks}
          disabled={checkingAll}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
        >
          {checkingAll ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
          Run Health Check Now
        </button>
      </div>

      {/* Provider cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {providers.map((p) => {
          const color = STATUS_COLORS[p.health.status] || "#ff4444";
          return (
            <button
              key={p.id}
              onClick={() => fetchDetail(p.id)}
              className="text-left rounded-xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5 hover:border-slate-700 transition-all"
            >
              {/* Status header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div
                    className="h-3 w-3 rounded-full"
                    style={{ backgroundColor: color, boxShadow: `0 0 12px ${color}` }}
                  />
                  <span className="text-sm font-medium text-white">{p.name}</span>
                </div>
                <span
                  className="text-xs font-medium px-2 py-0.5 rounded-full border"
                  style={{ borderColor: `${color}40`, backgroundColor: `${color}10`, color }}
                >
                  {STATUS_LABELS[p.health.status] || "Unknown"}
                </span>
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <p className="text-slate-500">Latency</p>
                  <p className="text-white font-medium mt-0.5">
                    {p.health.latencyMs > 0 ? `${p.health.latencyMs}ms` : "—"}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500">Last Check</p>
                  <p className="text-white font-medium mt-0.5">
                    {p.health.lastCheckedAt
                      ? new Date(p.health.lastCheckedAt).toLocaleTimeString()
                      : "Never"}
                  </p>
                </div>
              </div>

              {p.health.error && (
                <p className="mt-3 text-xs text-red-400/80 truncate" title={p.health.error}>
                  {p.health.error}
                </p>
              )}

              <p className="mt-3 text-xs text-cyan-400/60">Click for details →</p>
            </button>
          );
        })}
      </div>

      {providers.length === 0 && (
        <div className="text-center py-12">
          <HeartPulse className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No providers to monitor.</p>
        </div>
      )}

      {/* Detail modal */}
      {selectedDetail && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={() => setSelectedDetail(null)}
        >
          <div
            className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-2xl w-full shadow-2xl max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {detailLoading ? (
              <div className="flex items-center justify-center h-32">
                <Loader2 className="h-6 w-6 animate-spin text-cyan-400" />
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div
                      className="h-3 w-3 rounded-full"
                      style={{
                        backgroundColor: STATUS_COLORS[selectedDetail.status.status] || "#ff4444",
                        boxShadow: `0 0 12px ${STATUS_COLORS[selectedDetail.status.status] || "#ff4444"}`,
                      }}
                    />
                    <h3 className="text-lg font-bold text-white">
                      {selectedDetail.provider?.name || "Unknown"}
                    </h3>
                  </div>
                  <button
                    onClick={() => setSelectedDetail(null)}
                    className="text-slate-500 hover:text-white transition-colors text-sm"
                  >
                    ✕
                  </button>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-3 gap-3 mb-6">
                  <div className="rounded-lg bg-slate-800/60 p-3">
                    <p className="text-xs text-slate-500">Status</p>
                    <p
                      className="text-sm font-bold mt-1"
                      style={{ color: STATUS_COLORS[selectedDetail.status.status] || "#ff4444" }}
                    >
                      {STATUS_LABELS[selectedDetail.status.status] || "Unknown"}
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-800/60 p-3">
                    <p className="text-xs text-slate-500">Uptime (24h)</p>
                    <p className="text-sm font-bold text-white mt-1">
                      {selectedDetail.uptime.toFixed(1)}%
                    </p>
                  </div>
                  <div className="rounded-lg bg-slate-800/60 p-3">
                    <p className="text-xs text-slate-500">Last Latency</p>
                    <p className="text-sm font-bold text-white mt-1">
                      {selectedDetail.status.latencyMs > 0 ? `${selectedDetail.status.latencyMs}ms` : "—"}
                    </p>
                  </div>
                </div>

                {/* Latency chart */}
                <div className="mb-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Activity className="h-4 w-4 text-slate-500" />
                    <h4 className="text-sm font-medium text-slate-300">Latency (last 24h)</h4>
                  </div>
                  <LatencyChart history={selectedDetail.history} />
                </div>

                {selectedDetail.status.error && (
                  <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3 mb-4">
                    <p className="text-xs font-medium text-red-400">Last Error</p>
                    <p className="text-xs text-red-300/80 mt-1">{selectedDetail.status.error}</p>
                  </div>
                )}

                <div className="flex items-center justify-between text-xs text-slate-500">
                  <span>
                    Last checked:{" "}
                    {selectedDetail.status.lastCheckedAt
                      ? new Date(selectedDetail.status.lastCheckedAt).toLocaleString()
                      : "Never"}
                  </span>
                  <button
                    onClick={() => fetchDetail(selectedDetail.provider!.id)}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    <RefreshCw className="h-3 w-3" />
                    Refresh
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function LatencyChart({ history }: { history: HealthEntry[] }) {
  if (history.length === 0) {
    return (
      <div className="text-center py-8 text-xs text-slate-500">
        No health check data in this period
      </div>
    );
  }

  const maxLatency = Math.max(...history.map((h) => h.latencyMs), 100);
  const chartHeight = 120;

  return (
    <div className="flex items-end gap-px h-[120px] bg-slate-800/20 rounded-lg p-2 overflow-hidden">
      {history.slice(-80).map((entry, idx) => {
        const height = Math.max(2, (entry.latencyMs / maxLatency) * chartHeight);
        const color = STATUS_COLORS[entry.status] || "#ff4444";
        return (
          <div
            key={idx}
            className="flex-1 rounded-t-sm transition-all hover:opacity-80"
            style={{
              height: `${height}px`,
              backgroundColor: color,
              minWidth: "2px",
            }}
            title={`${new Date(entry.checkedAt).toLocaleTimeString()}: ${entry.latencyMs}ms (${entry.status})`}
          />
        );
      })}
    </div>
  );
}

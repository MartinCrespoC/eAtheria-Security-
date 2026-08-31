"use client";

import { useEffect, useState, useCallback } from "react";
import { Loader2, GitBranch, ArrowRight, Zap, CheckCircle2 } from "lucide-react";

interface FallbackProvider {
  id: string;
  name: string;
  slug: string;
}

interface FallbackRow {
  id: string;
  name: string;
  slug: string;
  isActive: boolean;
  fallbackProviderId: string | null;
  fallbackProvider: { id: string; name: string; slug: string } | null;
}

export function AIConfigFallback() {
  const [providers, setProviders] = useState<FallbackRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-configuration/fallback");
      if (res.ok) {
        setProviders(await res.json());
      }
    } catch {
      showMsg("error", "Failed to load fallback config");
    } finally {
      setLoading(false);
    }
  }, [showMsg]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  async function saveFallback(providerId: string, fallbackId: string) {
    setSaving(providerId);
    try {
      const res = await fetch("/api/admin/ai-configuration/fallback", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          providerId,
          fallbackProviderId: fallbackId || null,
        }),
      });
      if (res.ok) {
        showMsg("success", "Fallback updated");
        await fetchData();
      }
    } catch {
      showMsg("error", "Failed to save fallback");
    }
    setSaving(null);
  }

  async function testFailover(providerId: string) {
    setTesting(providerId);
    try {
      // Run a health check on the provider to simulate failover scenario
      const res = await fetch("/api/admin/ai-configuration/health", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ providerId }),
      });
      if (res.ok) {
        const data = await res.json();
        showMsg("success", `Health check: ${data.status} (${data.latencyMs}ms)`);
        await fetchData();
      }
    } catch {
      showMsg("error", "Failover test failed");
    }
    setTesting(null);
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
          <GitBranch className="h-5 w-5 text-cyan-400" />
          Fallback Chains
        </h2>
      </div>

      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
        <p className="text-xs text-slate-400">
          When a provider goes down, the system automatically falls back to the configured provider.
          Configure chains to ensure high availability.
        </p>
      </div>

      <div className="space-y-3">
        {providers.map((p) => {
          // Build the fallback chain
          const chain: FallbackProvider[] = [{ id: p.id, name: p.name, slug: p.slug }];
          if (p.fallbackProvider) {
            chain.push(p.fallbackProvider);
          }

          return (
            <div
              key={p.id}
              className="rounded-xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5"
            >
              <div className="flex items-center justify-between flex-wrap gap-4">
                {/* Chain visualization */}
                <div className="flex items-center gap-2 flex-wrap">
                  {chain.map((node, idx) => (
                    <div key={node.id} className="flex items-center gap-2">
                      {idx > 0 && <ArrowRight className="h-4 w-4 text-slate-600" />}
                      <div
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
                          idx === 0
                            ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-400"
                            : "border-purple-500/30 bg-purple-500/10 text-purple-400"
                        }`}
                      >
                        <span className="text-sm font-medium">{node.name}</span>
                        <span className="text-xs opacity-60 font-mono">{node.slug}</span>
                      </div>
                    </div>
                  ))}
                  {chain.length === 1 && (
                    <span className="text-xs text-slate-500 ml-2">No fallback configured</span>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  <select
                    defaultValue={p.fallbackProviderId || ""}
                    onChange={(e) => saveFallback(p.id, e.target.value)}
                    disabled={saving === p.id}
                    className="px-2 py-1.5 rounded-md bg-slate-800 border border-slate-700 text-white text-sm focus:border-cyan-500/50 focus:outline-none min-w-[180px]"
                  >
                    <option value="">— No fallback —</option>
                    {providers
                      .filter((other) => other.id !== p.id)
                      .map((other) => (
                        <option key={other.id} value={other.id}>
                          {other.name} ({other.slug})
                        </option>
                      ))}
                  </select>
                  {saving === p.id && <Loader2 className="h-3 w-3 animate-spin text-cyan-400" />}

                  <button
                    onClick={() => testFailover(p.id)}
                    disabled={testing === p.id}
                    title="Test Failover"
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors disabled:opacity-50"
                  >
                    {testing === p.id ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <Zap className="h-3 w-3" />
                    )}
                    Test Failover
                  </button>
                </div>
              </div>

              {/* Status */}
              <div className="mt-3 flex items-center gap-2 text-xs">
                {p.isActive ? (
                  <>
                    <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                    <span className="text-emerald-400">Active</span>
                  </>
                ) : (
                  <span className="text-slate-500">Inactive</span>
                )}
                {p.fallbackProvider && (
                  <>
                    <span className="text-slate-600">|</span>
                    <span className="text-slate-400">
                      Fallback: <span className="text-purple-400">{p.fallbackProvider.name}</span>
                    </span>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {providers.length === 0 && (
        <div className="text-center py-12">
          <GitBranch className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No providers configured.</p>
        </div>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  TestTube,
  Loader2,
  Power,
  PowerOff,
  RefreshCw,
  AlertTriangle,
  Zap,
  KeyRound,
  Ban,
} from "lucide-react";

interface ProviderHealth {
  status: string;
  latencyMs: number;
  error: string | null;
  lastCheckedAt: string | null;
}

interface Provider {
  id: string;
  slug: string;
  name: string;
  type: string;
  baseUrl: string | null;
  authType: string;
  isActive: boolean;
  hasApiKey: boolean;
  config: Record<string, unknown> | null;
  fallbackProviderId: string | null;
  maxTokensPerMonth: number | null;
  costLimitPerMonth: string | null;
  health: ProviderHealth;
  _count: { models: number; companies: number };
}

interface ModelInfo {
  id: string;
  name: string;
  modelId: string;
  isDefault: boolean;
  isActive: boolean;
  providerId: string | null;
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

const PROVIDER_ICONS: Record<string, string> = {
  gemini: "🔮",
  "google-gemini-cli": "🌐",
  openai: "🤖",
  chatgpt: "💬",
  anthropic: "🧠",
  openrouter: "🔀",
  copilot: "🐙",
  deepseek: "🔍",
  xai: "⚡",
  mistral: "🌬️",
  "azure-openai": "☁️",
  "aws-bedrock": "🏗️",
  "vertex-ai": "🔺",
  nvidia: "💚",
  qwen: "🐉",
  kimi: "🌙",
  minimax: "📐",
  huggingface: "🤗",
  "grok-cli": "⚡",
  "qoder-cli": "🛠️",
  custom: "🔧",
};

type GroupId = "connected" | "needsSetup" | "disabled";

const GROUP_META: Record<GroupId, { label: string; icon: React.ComponentType<{ className?: string }>; color: string }> = {
  connected: { label: "Conectados", icon: Zap, color: "text-emerald-400" },
  needsSetup: { label: "Necesitan configuración", icon: KeyRound, color: "text-amber-400" },
  disabled: { label: "Desactivados", icon: Ban, color: "text-slate-500" },
};

export function AIConfigProviders() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-configuration");
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
        setModels(data.models || []);
      }
    } catch {
      showMsg("error", "Failed to load providers");
    } finally {
      setLoading(false);
    }
  }, [showMsg]);

  // Which provider hosts the default model?
  const defaultModelProviderId = useMemo(() => {
    const def = models.find((m) => m.isDefault);
    return def?.providerId || null;
  }, [models]);

  const defaultModelName = useMemo(() => {
    const def = models.find((m) => m.isDefault);
    return def?.name || null;
  }, [models]);

  // Group: Connected (active + has key) → Needs Setup (active, no key) → Disabled
  const groups = useMemo(() => {
    const connected: Provider[] = [];
    const needsSetup: Provider[] = [];
    const disabled: Provider[] = [];
    for (const p of providers) {
      if (!p.isActive) disabled.push(p);
      else if (p.hasApiKey) connected.push(p);
      else needsSetup.push(p);
    }
    return { connected, needsSetup, disabled };
  }, [providers]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  async function testProvider(id: string) {
    setActionLoading(`test-${id}`);
    try {
      const res = await fetch("/api/admin/ai-configuration/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ providerId: id }),
      });
      const data = await res.json();
      if (data.ok) {
        showMsg("success", `${id} connection successful`);
      } else {
        showMsg("error", data.error || "Connection failed");
      }
      await fetchData();
    } catch {
      showMsg("error", "Test failed");
    }
    setActionLoading(null);
  }

  async function toggleActive(id: string, currentActive: boolean) {
    setActionLoading(id);
    try {
      await fetch("/api/admin/ai-providers/" + id, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isActive: !currentActive }),
      });
      showMsg("success", currentActive ? "Provider deactivated" : "Provider activated");
      await fetchData();
    } catch {
      showMsg("error", "Failed to update");
    }
    setActionLoading(null);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  function renderProviderRow(p: Provider) {
    const color = STATUS_COLORS[p.health.status] || "#64748b";
    const isInUse = p.id === defaultModelProviderId;
    const hasBeenTested = !!p.health.lastCheckedAt;
    return (
      <tr
        key={p.id}
        className={`hover:bg-slate-800/20 transition-colors ${
          isInUse ? "bg-emerald-500/[0.04]" : ""
        }`}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-3">
            {/* Connection status dot: green = tested OK, red = failed, gray = untested */}
            <div
              className="h-2.5 w-2.5 rounded-full flex-shrink-0"
              title={
                !hasBeenTested
                  ? "Sin probar"
                  : p.health.status === "healthy"
                  ? "Conexión OK"
                  : p.health.status === "degraded"
                  ? "Degradado"
                  : "Falló la conexión"
              }
              style={{
                backgroundColor: !hasBeenTested ? "#64748b" : color,
                boxShadow: hasBeenTested ? `0 0 8px ${color}` : "none",
              }}
            />
            <span className="text-lg leading-none">{PROVIDER_ICONS[p.slug] || "🔧"}</span>
            <div>
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium text-white">{p.name}</p>
                {isInUse && (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide bg-emerald-500/15 text-emerald-400 border border-emerald-500/40 ring-1 ring-emerald-500/30">
                    <Zap className="h-2.5 w-2.5" />
                    En uso
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 font-mono">
                {p.slug}
                {isInUse && defaultModelName && (
                  <span className="text-emerald-500/80 ml-2">→ {defaultModelName}</span>
                )}
              </p>
            </div>
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-slate-300">{p.type}</td>
        <td className="px-4 py-3 text-center">
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border"
            style={{
              borderColor: `${!hasBeenTested ? "#64748b" : color}40`,
              backgroundColor: `${!hasBeenTested ? "#64748b" : color}10`,
              color: !hasBeenTested ? "#94a3b8" : color,
            }}
          >
            {!hasBeenTested ? "Sin probar" : STATUS_LABELS[p.health.status] || "Unknown"}
          </span>
        </td>
        <td className="px-4 py-3 text-center text-sm text-slate-300">
          {p.health.latencyMs > 0 ? `${p.health.latencyMs}ms` : "—"}
        </td>
        <td className="px-4 py-3 text-center text-sm text-slate-300">{p._count.models}</td>
        <td className="px-4 py-3 text-center text-sm text-slate-300">{p._count.companies}</td>
        <td className="px-4 py-3">
          <div className="flex items-center justify-end gap-1.5">
            <button
              onClick={() => testProvider(p.id)}
              disabled={actionLoading === `test-${p.id}`}
              title="Test Connection"
              className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors"
            >
              {actionLoading === `test-${p.id}` ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <TestTube className="h-3 w-3" />
              )}
              Test
            </button>
            <button
              onClick={() => toggleActive(p.id, p.isActive)}
              disabled={!!actionLoading}
              title={p.isActive ? "Deactivate" : "Activate"}
              className={`flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors ${
                p.isActive
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20"
                  : "bg-slate-800/40 text-slate-500 border-slate-700/60 hover:text-white"
              }`}
            >
              {p.isActive ? <Power className="h-3 w-3" /> : <PowerOff className="h-3 w-3" />}
              {p.isActive ? "On" : "Off"}
            </button>
          </div>
        </td>
      </tr>
    );
  }

  function renderGroup(groupId: GroupId, items: Provider[]) {
    if (items.length === 0) return null;
    const meta = GROUP_META[groupId];
    const Icon = meta.icon;
    return (
      <div key={groupId}>
        <div className="flex items-center gap-2 mb-2">
          <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
          <span className={`text-xs font-semibold uppercase tracking-wider ${meta.color}`}>
            {meta.label}
          </span>
          <span className="text-xs text-slate-600">({items.length})</span>
        </div>
        <div
          className={`rounded-xl border backdrop-blur-xl overflow-hidden ${
            groupId === "connected"
              ? "border-emerald-500/20 bg-slate-900/40"
              : groupId === "needsSetup"
              ? "border-amber-500/20 bg-slate-900/40"
              : "border-slate-800/60 bg-slate-900/30 opacity-70"
          }`}
        >
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/60 bg-slate-900/60">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Proveedor</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Tipo</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wider">Estado</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wider">Latencia</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wider">Modelos</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wider">Empresas</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {items.map(renderProviderRow)}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
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
        <div>
          <h2 className="text-lg font-semibold text-white">Proveedores IA</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Conecta y gestiona los proveedores de IA del sistema. El proveedor con el modelo default se marca como <span className="text-emerald-400 font-medium">EN USO</span>.
          </p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-400 hover:text-white transition-colors border border-slate-700/60"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Actualizar
        </button>
      </div>

      {/* Grouped provider tables */}
      {renderGroup("connected", groups.connected)}
      {renderGroup("needsSetup", groups.needsSetup)}
      {renderGroup("disabled", groups.disabled)}

      {/* Status legend */}
      <div className="flex items-center gap-4 text-xs text-slate-500 flex-wrap">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "#00ff88" }} />
          Conexión OK
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "#ffaa00" }} />
          Degradado
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "#ff4444" }} />
          Falló conexión
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "#64748b" }} />
          Sin probar
        </span>
      </div>

      {providers.length === 0 && (
        <div className="text-center py-12">
          <AlertTriangle className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No hay proveedores configurados.</p>
          <p className="text-slate-500 text-sm mt-1">Agrega un proveedor para comenzar a usar el Motor IA.</p>
        </div>
      )}
    </div>
  );
}

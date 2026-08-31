"use client";

import { useEffect, useState, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import {
  Brain,
  Star,
  Trash2,
  Power,
  PowerOff,
  Plus,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronUp,
  Check,
} from "lucide-react";

interface AIModel {
  id: string;
  name: string;
  provider: string;
  modelId: string;
  inputTokenCost: string | number;
  outputTokenCost: string | number;
  maxInputTokens: number;
  maxOutputTokens: number;
  isActive: boolean;
  isDefault: boolean;
}

interface AvailableModel {
  modelId: string;
  displayName: string;
  description: string;
  inputTokenLimit: number;
  outputTokenLimit: number;
  alreadyAdded: boolean;
}

interface ProviderOption {
  id: string;
  slug: string;
  name: string;
  type: string;
  isActive: boolean;
}

export function AIModelsManager() {
  const [models, setModels] = useState<AIModel[]>([]);
  const [available, setAvailable] = useState<AvailableModel[]>([]);
  const [providers, setProviders] = useState<ProviderOption[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [loadingAvailable, setLoadingAvailable] = useState(false);
  const [showAvailable, setShowAvailable] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchModels = useCallback(async () => {
    const res = await fetch("/api/admin/ai-models");
    if (res.ok) setModels(await res.json());
  }, []);

  const fetchProviders = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-providers");
      if (res.ok) {
        const data = await res.json();
        const active = data.filter((p: ProviderOption & { hasApiKey?: boolean }) => p.isActive);
        setProviders(active);
        if (active.length > 0 && !selectedProvider) {
          setSelectedProvider(active[0].id);
        }
      }
    } catch { /* ignore */ }
  }, [selectedProvider]);

  const fetchAvailable = useCallback(async (providerId?: string) => {
    const pid = providerId || selectedProvider;
    if (!pid) return;
    setLoadingAvailable(true);
    try {
      const res = await fetch(`/api/admin/ai-providers/${pid}/models`);
      if (res.ok) {
        setAvailable(await res.json());
      } else {
        // Fallback to legacy Google AI endpoint
        const legacyRes = await fetch("/api/admin/ai-models/available");
        if (legacyRes.ok) {
          setAvailable(await legacyRes.json());
        } else {
          const err = await legacyRes.json();
          showMsg("error", err.error || "Error al cargar modelos disponibles");
        }
      }
    } catch {
      showMsg("error", "Error de conexión");
    }
    setLoadingAvailable(false);
  }, [showMsg, selectedProvider]);

  useEffect(() => {
    Promise.all([fetchModels(), fetchProviders()]).finally(() => setLoading(false));
  }, [fetchModels, fetchProviders]);

  async function setDefault(id: string) {
    setActionLoading(id);
    const res = await fetch(`/api/admin/ai-models/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isDefault: true }),
    });
    if (res.ok) {
      showMsg("success", "Modelo por defecto actualizado");
      await fetchModels();
    } else {
      showMsg("error", "Error al actualizar");
    }
    setActionLoading(null);
  }

  async function toggleActive(id: string, currentActive: boolean) {
    setActionLoading(id);
    const res = await fetch(`/api/admin/ai-models/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: !currentActive }),
    });
    if (res.ok) {
      showMsg("success", currentActive ? "Modelo desactivado" : "Modelo activado");
      await fetchModels();
    } else {
      showMsg("error", "Error al actualizar");
    }
    setActionLoading(null);
  }

  async function deleteModel(id: string) {
    if (!confirm("¿Eliminar este modelo?")) return;
    setActionLoading(id);
    const res = await fetch(`/api/admin/ai-models/${id}`, { method: "DELETE" });
    if (res.ok) {
      showMsg("success", "Modelo eliminado");
      await fetchModels();
    } else {
      showMsg("error", "Error al eliminar");
    }
    setActionLoading(null);
  }

  async function addModel(avail: AvailableModel) {
    setActionLoading(avail.modelId);
    const providerObj = providers.find((p) => p.id === selectedProvider);
    const res = await fetch("/api/admin/ai-models", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: avail.displayName,
        provider: providerObj?.slug || "gemini",
        modelId: avail.modelId,
        inputTokenCost: 0,
        outputTokenCost: 0,
        maxInputTokens: avail.inputTokenLimit || 1_000_000,
        maxOutputTokens: avail.outputTokenLimit || 65536,
        isDefault: false,
        providerId: selectedProvider || undefined,
      }),
    });
    if (res.ok) {
      showMsg("success", `${avail.displayName} agregado`);
      await fetchModels();
      // Update available list
      setAvailable((prev) =>
        prev.map((m) => (m.modelId === avail.modelId ? { ...m, alreadyAdded: true } : m))
      );
    } else {
      const err = await res.json();
      showMsg("error", err.error || "Error al agregar modelo");
    }
    setActionLoading(null);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Modelos de IA</h1>
          <p className="text-slate-400 mt-1">
            Gestiona modelos de múltiples proveedores, cambia el default y agrega nuevos
          </p>
        </div>
        <button
          onClick={() => {
            setShowAvailable(!showAvailable);
            if (!showAvailable && available.length === 0) fetchAvailable();
          }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm font-medium"
        >
          <Plus className="h-4 w-4" />
          Agregar Modelo
          {showAvailable ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        </button>
      </div>

      {/* Notification */}
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

      {/* Available Models Panel */}
      {showAvailable && (
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/80 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">
              Modelos Disponibles
            </h2>
            <div className="flex items-center gap-3">
              <select
                value={selectedProvider}
                onChange={(e) => {
                  setSelectedProvider(e.target.value);
                  setAvailable([]);
                  fetchAvailable(e.target.value);
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-white text-xs focus:border-cyan-500/50 focus:outline-none"
              >
                {providers.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
              <button
                onClick={() => fetchAvailable()}
                disabled={loadingAvailable}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loadingAvailable ? "animate-spin" : ""}`} />
                Refrescar
              </button>
            </div>
          </div>

          {loadingAvailable ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
              <span className="ml-2 text-slate-400 text-sm">Consultando API del provider...</span>
            </div>
          ) : available.length === 0 ? (
            <p className="text-slate-500 text-sm text-center py-8">
              No se encontraron modelos. Verifica las credenciales del provider.
            </p>
          ) : (
            <div className="max-h-96 overflow-y-auto space-y-2 pr-1">
              {available.map((m) => (
                <div
                  key={m.modelId}
                  className={`flex items-center justify-between rounded-lg border p-3 transition-colors ${
                    m.alreadyAdded
                      ? "border-slate-800/40 bg-slate-800/20 opacity-60"
                      : "border-slate-700/60 bg-slate-800/40 hover:bg-slate-800/60"
                  }`}
                >
                  <div className="flex-1 min-w-0 mr-3">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-white truncate">{m.displayName}</p>
                      <span className="text-[10px] font-mono text-slate-500 shrink-0">{m.modelId}</span>
                    </div>
                    <p className="text-xs text-slate-500 truncate mt-0.5">{m.description}</p>
                    <div className="flex gap-3 mt-1 text-[10px] text-slate-600">
                      <span>Input: {m.inputTokenLimit?.toLocaleString() || "?"} tokens</span>
                      <span>Output: {m.outputTokenLimit?.toLocaleString() || "?"} tokens</span>
                    </div>
                  </div>
                  {m.alreadyAdded ? (
                    <span className="flex items-center gap-1 text-xs text-emerald-500 shrink-0">
                      <Check className="h-3.5 w-3.5" /> Agregado
                    </span>
                  ) : (
                    <button
                      onClick={() => addModel(m)}
                      disabled={actionLoading === m.modelId}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-xs font-medium shrink-0"
                    >
                      {actionLoading === m.modelId ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Plus className="h-3 w-3" />
                      )}
                      Agregar
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Current Models Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {models.map((model) => (
          <div
            key={model.id}
            className={`rounded-xl border p-5 transition-all ${
              model.isDefault
                ? "border-cyan-500/40 bg-cyan-500/5 ring-1 ring-cyan-500/20"
                : model.isActive
                ? "border-slate-800/60 bg-slate-900/50"
                : "border-slate-800/30 bg-slate-900/20 opacity-60"
            }`}
          >
            {/* Header */}
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div
                  className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                    model.isDefault
                      ? "bg-gradient-to-br from-cyan-500/30 to-purple-500/30"
                      : "bg-gradient-to-br from-violet-500/20 to-purple-500/20"
                  }`}
                >
                  <Brain className={`h-5 w-5 ${model.isDefault ? "text-cyan-400" : "text-violet-400"}`} />
                </div>
                <div>
                  <h3 className="font-semibold text-white">{model.name}</h3>
                  <p className="text-xs text-slate-500 font-mono">{model.modelId}</p>
                </div>
              </div>
              <div className="flex gap-1">
                {model.isDefault && <Badge variant="info">Default</Badge>}
                <Badge variant={model.isActive ? "success" : "default"}>
                  {model.isActive ? "Activo" : "Inactivo"}
                </Badge>
              </div>
            </div>

            {/* Stats */}
            <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-slate-500">Input:</span>{" "}
                <span className="text-white font-mono">
                  ${Number(model.inputTokenCost).toFixed(4)}/1M
                </span>
              </div>
              <div>
                <span className="text-slate-500">Output:</span>{" "}
                <span className="text-white font-mono">
                  ${Number(model.outputTokenCost).toFixed(4)}/1M
                </span>
              </div>
              <div>
                <span className="text-slate-500">Max tokens:</span>{" "}
                <span className="text-white">{model.maxInputTokens?.toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-500">Tipo:</span>{" "}
                <span className="text-white capitalize">{model.provider}</span>
              </div>
            </div>

            {/* Actions */}
            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center gap-2">
              {!model.isDefault && model.isActive && (
                <button
                  onClick={() => setDefault(model.id)}
                  disabled={actionLoading === model.id}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition-colors"
                  title="Establecer como modelo por defecto"
                >
                  {actionLoading === model.id ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Star className="h-3 w-3" />
                  )}
                  Default
                </button>
              )}
              {model.isDefault && (
                <span className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-cyan-400">
                  <Star className="h-3 w-3 fill-current" />
                  Modelo principal
                </span>
              )}
              <button
                onClick={() => toggleActive(model.id, model.isActive)}
                disabled={actionLoading === model.id || model.isDefault}
                className={`flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium border transition-colors ${
                  model.isActive
                    ? "bg-slate-800/40 text-slate-400 border-slate-700/60 hover:bg-red-500/10 hover:text-red-400 hover:border-red-500/30"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20"
                } ${model.isDefault ? "opacity-30 cursor-not-allowed" : ""}`}
                title={model.isActive ? "Desactivar" : "Activar"}
              >
                {model.isActive ? <PowerOff className="h-3 w-3" /> : <Power className="h-3 w-3" />}
                {model.isActive ? "Desactivar" : "Activar"}
              </button>
              {!model.isDefault && (
                <button
                  onClick={() => deleteModel(model.id)}
                  disabled={actionLoading === model.id}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-colors ml-auto"
                  title="Eliminar modelo"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

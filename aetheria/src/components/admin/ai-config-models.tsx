"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { Loader2, RefreshCw, Boxes, Star, Zap, Plus, X, ChevronDown } from "lucide-react";

interface AIProviderInfo {
  id: string;
  name: string;
  slug: string;
  isActive?: boolean;
}

interface Model {
  id: string;
  name: string;
  modelId: string;
  provider: string;
  inputTokenCost: string;
  outputTokenCost: string;
  maxInputTokens: number;
  maxOutputTokens: number;
  isActive: boolean;
  isDefault: boolean;
  providerId: string | null;
  aiProvider: AIProviderInfo | null;
}

interface CatalogModel {
  modelId: string;
  name?: string;
  alreadyAdded: boolean;
}

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

export function AIConfigModels() {
  const [models, setModels] = useState<Model[]>([]);
  const [providers, setProviders] = useState<AIProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string>("all");
  const [showCatalog, setShowCatalog] = useState(false);
  const [catalogModels, setCatalogModels] = useState<CatalogModel[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [expandedProvider, setExpandedProvider] = useState<string | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-configuration");
      if (res.ok) {
        const data = await res.json();
        setModels(data.models || []);
        setProviders(data.providers || []);
      }
    } catch {
      showMsg("error", "Failed to load models");
    } finally {
      setLoading(false);
    }
  }, [showMsg]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Filter models by selected provider
  const filteredModels = useMemo(() => {
    if (selectedProvider === "all") return models;
    return models.filter((m) => (m.aiProvider?.id || "unassigned") === selectedProvider);
  }, [models, selectedProvider]);

  // Group filtered models by provider
  const modelsByProvider = useMemo(() => {
    return filteredModels.reduce((acc, model) => {
      const key = model.aiProvider?.id || "unassigned";
      if (!acc[key]) acc[key] = [];
      acc[key].push(model);
      return acc;
    }, {} as Record<string, Model[]>);
  }, [filteredModels]);

  async function toggleModel(id: string, currentActive: boolean) {
    setActionLoading(`toggle-${id}`);
    try {
      const res = await fetch(`/api/admin/ai-models/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isActive: !currentActive }),
      });
      if (res.ok) {
        showMsg("success", currentActive ? "Model deactivated" : "Model activated");
        await fetchData();
      }
    } catch {
      showMsg("error", "Failed to toggle model");
    }
    setActionLoading(null);
  }

  async function setDefaultModel(id: string) {
    setActionLoading(`default-${id}`);
    try {
      const res = await fetch(`/api/admin/ai-models/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isDefault: true }),
      });
      if (res.ok) {
        showMsg("success", "Default model updated");
        await fetchData();
      }
    } catch {
      showMsg("error", "Failed to set default");
    }
    setActionLoading(null);
  }

  async function loadCatalog() {
    const providerId = selectedProvider === "all" ? providers[0]?.id : selectedProvider;
    if (!providerId) {
      showMsg("error", "Selecciona un proveedor específico para agregar modelos");
      return;
    }
    setShowCatalog(true);
    setCatalogLoading(true);
    setCatalogModels([]);
    try {
      const res = await fetch(`/api/admin/ai-providers/${providerId}/models`);
      if (res.ok) {
        const data = await res.json();
        setCatalogModels(data);
      } else {
        const err = await res.json().catch(() => ({}));
        showMsg("error", err.error || "No se pudieron obtener modelos del catálogo");
        setShowCatalog(false);
      }
    } catch {
      showMsg("error", "Error de red al obtener catálogo");
      setShowCatalog(false);
    }
    setCatalogLoading(false);
  }

  async function addModelFromCatalog(catalogModel: CatalogModel) {
    const providerId = selectedProvider === "all" ? providers[0]?.id : selectedProvider;
    const provider = providers.find((p) => p.id === providerId);
    setActionLoading(`add-${catalogModel.modelId}`);
    try {
      const res = await fetch("/api/admin/ai-models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: catalogModel.name || catalogModel.modelId,
          modelId: catalogModel.modelId,
          provider: provider?.slug || "custom",
          providerId: providerId,
        }),
      });
      if (res.ok) {
        showMsg("success", `Modelo ${catalogModel.modelId} agregado`);
        setCatalogModels((prev) =>
          prev.map((m) => (m.modelId === catalogModel.modelId ? { ...m, alreadyAdded: true } : m))
        );
        await fetchData();
      } else {
        const err = await res.json().catch(() => ({}));
        showMsg("error", err.error || "Error al agregar modelo");
      }
    } catch {
      showMsg("error", "Error de red");
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

  const catalogProvider = selectedProvider === "all" ? providers[0] : providers.find((p) => p.id === selectedProvider);

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

      {/* Header + Provider Selector */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Modelos IA</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            El modelo default se usa en todos los análisis. Banner <span className="text-emerald-400 font-medium">MODELO ACTIVO</span> indica el modelo en uso.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Provider Selector */}
          <div className="relative">
            <select
              value={selectedProvider}
              onChange={(e) => { setSelectedProvider(e.target.value); setShowCatalog(false); }}
              className="appearance-none pl-3 pr-8 py-1.5 rounded-lg text-xs font-medium bg-slate-800/60 text-white border border-slate-700/60 focus:border-cyan-500/50 focus:outline-none cursor-pointer"
            >
              <option value="all">Todos los proveedores</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {PROVIDER_ICONS[p.slug] || "🔧"} {p.name}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-500 pointer-events-none" />
          </div>
          {/* Add Model from Catalog */}
          <button
            onClick={loadCatalog}
            disabled={selectedProvider === "all" && providers.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Agregar del catálogo
          </button>
          <button
            onClick={fetchData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/60 text-slate-400 hover:text-white transition-colors border border-slate-700/60"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Actualizar
          </button>
        </div>
      </div>

      {/* Catalog Panel */}
      {showCatalog && (
        <div className="rounded-xl border border-cyan-500/30 bg-slate-900/60 backdrop-blur-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 bg-cyan-500/5 border-b border-cyan-500/20">
            <div className="flex items-center gap-2">
              <span className="text-sm">{PROVIDER_ICONS[catalogProvider?.slug || "custom"] || "🔧"}</span>
              <span className="text-sm font-medium text-white">
                Catálogo: {catalogProvider?.name || "Proveedor"}
              </span>
              <span className="text-xs text-slate-500">
                — modelos disponibles para agregar
              </span>
            </div>
            <button onClick={() => setShowCatalog(false)} className="text-slate-500 hover:text-white transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-64 overflow-y-auto p-3 space-y-1">
            {catalogLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
                <span className="ml-2 text-sm text-slate-400">Cargando catálogo...</span>
              </div>
            ) : catalogModels.length === 0 ? (
              <p className="text-center text-sm text-slate-500 py-6">No se encontraron modelos en el catálogo.</p>
            ) : (
              catalogModels.map((cm) => (
                <div key={cm.modelId} className="flex items-center justify-between px-3 py-2 rounded-lg hover:bg-slate-800/40 transition-colors">
                  <span className="text-sm text-slate-300 font-mono">{cm.name || cm.modelId}</span>
                  {cm.alreadyAdded ? (
                    <span className="text-xs text-emerald-400 font-medium px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30">
                      ✓ Agregado
                    </span>
                  ) : (
                    <button
                      onClick={() => addModelFromCatalog(cm)}
                      disabled={actionLoading === `add-${cm.modelId}`}
                      className="flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                    >
                      {actionLoading === `add-${cm.modelId}` ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Plus className="h-3 w-3" />
                      )}
                      Agregar
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Models grouped by provider */}
      {Object.entries(modelsByProvider).map(([providerId, providerModels]) => {
        const provider = providers.find((p) => p.id === providerId);
        const providerName = provider?.name || "Sin asignar";
        const providerSlug = provider?.slug || "custom";
        const isExpanded = expandedProvider === providerId || Object.keys(modelsByProvider).length === 1;
        const sortedModels = [...providerModels].sort((a, b) => {
          if (a.isDefault !== b.isDefault) return a.isDefault ? -1 : 1;
          if (a.isActive !== b.isActive) return a.isActive ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        const hasDefault = providerModels.some((m) => m.isDefault);

        return (
          <div
            key={providerId}
            className={`rounded-xl border backdrop-blur-xl overflow-hidden ${
              hasDefault ? "border-emerald-500/30 bg-slate-900/40" : "border-slate-800/60 bg-slate-900/40"
            }`}
          >
            <button
              onClick={() => setExpandedProvider(isExpanded ? null : providerId)}
              className="w-full flex items-center justify-between px-4 py-3 bg-slate-900/60 hover:bg-slate-800/40 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="text-base leading-none">{PROVIDER_ICONS[providerSlug] || "🔧"}</span>
                <span className="text-sm font-medium text-white">{providerName}</span>
                <span className="text-xs text-slate-500">({providerModels.length} modelos)</span>
                {hasDefault && (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide bg-emerald-500/15 text-emerald-400 border border-emerald-500/40">
                    <Zap className="h-2.5 w-2.5" />
                    En uso
                  </span>
                )}
              </div>
              <span className="text-xs text-slate-500">{isExpanded ? "− Colapsar" : "+ Expandir"}</span>
            </button>

            {isExpanded && (
              <div className="divide-y divide-slate-800/40">
                {sortedModels.map((model) => (
                  <div
                    key={model.id}
                    className={`px-4 py-3 transition-colors ${
                      model.isDefault
                        ? "bg-emerald-500/[0.05] hover:bg-emerald-500/[0.08]"
                        : model.isActive
                        ? "hover:bg-slate-800/20"
                        : "hover:bg-slate-800/20 opacity-60"
                    }`}
                  >
                    {model.isDefault && (
                      <div className="mb-2.5 flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/40 px-3 py-1.5 ring-1 ring-emerald-500/20">
                        <Zap className="h-3.5 w-3.5 text-emerald-400" />
                        <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                          Modelo activo
                        </span>
                        <span className="text-[11px] text-emerald-500/80">
                          — usado en todos los análisis del sistema
                        </span>
                      </div>
                    )}
                    <div className="flex items-center justify-between flex-wrap gap-3">
                      <div className="flex items-center gap-3">
                        {model.isDefault ? (
                          <Star className="h-4 w-4 text-amber-400 fill-amber-400" />
                        ) : (
                          <span className="h-4 w-4" />
                        )}
                        <div>
                          <p className="text-sm font-medium text-white">{model.name}</p>
                          <p className="text-xs text-slate-500 font-mono">
                            {model.modelId}
                            <span className="ml-2 text-slate-600">
                              {PROVIDER_ICONS[providerSlug] || "🔧"} {providerName}
                            </span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        <div className="text-xs text-right">
                          <p className="text-slate-400">
                            In: <span className="text-cyan-400">${Number(model.inputTokenCost).toFixed(2)}/M</span>
                          </p>
                          <p className="text-slate-400">
                            Out: <span className="text-cyan-400">${Number(model.outputTokenCost).toFixed(2)}/M</span>
                          </p>
                        </div>

                        <div className="text-xs text-slate-500 text-right">
                          <p>Ctx: {(model.maxInputTokens / 1000).toFixed(0)}K</p>
                          <p>Out: {(model.maxOutputTokens / 1000).toFixed(0)}K</p>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => setDefaultModel(model.id)}
                            disabled={actionLoading === `default-${model.id}` || model.isDefault}
                            title="Marcar como default"
                            className={`flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors ${
                              model.isDefault
                                ? "bg-amber-500/10 text-amber-400 border-amber-500/30 cursor-default"
                                : "bg-slate-800/40 text-slate-400 border-slate-700/60 hover:text-white"
                            }`}
                          >
                            {actionLoading === `default-${model.id}` ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Star className="h-3 w-3" />
                            )}
                            Default
                          </button>
                          <button
                            onClick={() => toggleModel(model.id, model.isActive)}
                            disabled={actionLoading === `toggle-${model.id}`}
                            className={`flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors ${
                              model.isActive
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                : "bg-slate-800/40 text-slate-500 border-slate-700/60 hover:text-white"
                            }`}
                          >
                            {actionLoading === `toggle-${model.id}` ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : null}
                            {model.isActive ? "Activo" : "Inactivo"}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {filteredModels.length === 0 && (
        <div className="text-center py-12">
          <Boxes className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">
            {selectedProvider === "all"
              ? "No hay modelos configurados."
              : "No hay modelos para este proveedor."}
          </p>
          <p className="text-slate-500 text-sm mt-1">
            Usa &quot;Agregar del catálogo&quot; para añadir modelos dinámicamente.
          </p>
        </div>
      )}
    </div>
  );
}

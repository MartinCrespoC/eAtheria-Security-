"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Brain,
  Boxes,
  Gauge,
  HeartPulse,
  GitBranch,
  Cpu,
  CheckCircle2,
  CircleDashed,
  ArrowRight,
  Sparkles,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { AIConfigProviders } from "./ai-config-providers";
import { AIConfigModels } from "./ai-config-models";
import { AIConfigLimits } from "./ai-config-limits";
import { AIConfigHealth } from "./ai-config-health";
import { AIConfigFallback } from "./ai-config-fallback";

type TabId = "providers" | "models" | "limits" | "health" | "fallback";

interface Tab {
  id: TabId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  component: React.ComponentType;
}

const TABS: Tab[] = [
  { id: "providers", label: "Proveedores", icon: Brain, component: AIConfigProviders },
  { id: "models", label: "Modelos", icon: Boxes, component: AIConfigModels },
  { id: "limits", label: "Límites", icon: Gauge, component: AIConfigLimits },
  { id: "health", label: "Salud", icon: HeartPulse, component: AIConfigHealth },
  { id: "fallback", label: "Fallback", icon: GitBranch, component: AIConfigFallback },
];

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

// Shape of the active stack summary
interface ActiveStack {
  provider: {
    id: string;
    name: string;
    slug: string;
    isActive: boolean;
    hasApiKey: boolean;
    health: "healthy" | "degraded" | "unhealthy" | "unknown";
  } | null;
  defaultModel: {
    id: string;
    name: string;
    modelId: string;
    provider: string;
  } | null;
  activeProviderCount: number;
  activeModelCount: number;
  loading: boolean;
}

export function AIConfiguration() {
  const [activeTab, setActiveTab] = useState<TabId>("providers");
  const [stack, setStack] = useState<ActiveStack>({
    provider: null,
    defaultModel: null,
    activeProviderCount: 0,
    activeModelCount: 0,
    loading: true,
  });

  const fetchStack = useCallback(async () => {
    try {
      const [providersRes, modelsRes] = await Promise.all([
        fetch("/api/admin/ai-providers"),
        fetch("/api/admin/ai-models"),
      ]);

      let provider: ActiveStack["provider"] = null;
      let defaultModel: ActiveStack["defaultModel"] = null;
      let activeProviderCount = 0;
      let activeModelCount = 0;

      if (providersRes.ok) {
        const providers = await providersRes.json();
        const active = providers.filter(
          (p: { isActive: boolean }) => p.isActive
        );
        activeProviderCount = active.length;

        // Prefer the provider that hosts the default model, else first active
        const configured = active.filter(
          (p: { hasApiKey?: boolean; authType?: string }) =>
            p.hasApiKey || p.authType === "none" || p.authType === "oauth"
        );
        const chosen = configured[0] || active[0] || null;
        if (chosen) {
          provider = {
            id: chosen.id,
            name: chosen.name,
            slug: chosen.slug,
            isActive: chosen.isActive,
            hasApiKey:
              chosen.hasApiKey ||
              chosen.authType === "none" ||
              chosen.authType === "oauth",
            health: "unknown",
          };
        }
      }

      if (modelsRes.ok) {
        const models = await modelsRes.json();
        activeModelCount = models.filter(
          (m: { isActive: boolean }) => m.isActive
        ).length;
        const def = models.find((m: { isDefault: boolean }) => m.isDefault);
        if (def) {
          defaultModel = {
            id: def.id,
            name: def.name,
            modelId: def.modelId,
            provider: def.provider,
          };
        }
      }

      setStack({ provider, defaultModel, activeProviderCount, activeModelCount, loading: false });
    } catch {
      setStack((prev) => ({ ...prev, loading: false }));
    }
  }, []);

  useEffect(() => {
    fetchStack();
  }, [fetchStack]);

  const currentTab = TABS.find((t) => t.id === activeTab)!;
  const ActiveComponent = currentTab.component;

  const needsSetup = !stack.loading && (!stack.provider || !stack.defaultModel);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Cpu className="h-6 w-6 text-cyan-400" />
          Motor IA
        </h1>
        <p className="text-slate-400 mt-1">
          Configuración central de proveedores, modelos, límites y salud del motor de análisis
        </p>
      </div>

      {/* Active Stack Status Bar */}
      <ActiveStackBar stack={stack} onNavigate={setActiveTab} />

      {/* Setup Guide (shown when not fully configured) */}
      {needsSetup && (
        <SetupGuide
          hasProvider={!!stack.provider}
          hasModel={!!stack.defaultModel}
          onNavigate={setActiveTab}
        />
      )}

      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-1 rounded-xl border border-slate-800/60 bg-slate-900/40 p-1 backdrop-blur-xl">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
                isActive
                  ? "bg-cyan-500/10 border border-cyan-500/30 text-cyan-400"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/40 border border-transparent"
              )}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        <ActiveComponent />
      </div>
    </div>
  );
}

// ==================== ACTIVE STACK BAR ====================
function ActiveStackBar({
  stack,
  onNavigate,
}: {
  stack: ActiveStack;
  onNavigate: (tab: TabId) => void;
}) {
  if (stack.loading) {
    return (
      <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-5 flex items-center justify-center h-24">
        <Loader2 className="h-5 w-5 animate-spin text-slate-500" />
      </div>
    );
  }

  const providerReady = stack.provider && stack.provider.hasApiKey;

  return (
    <div className="rounded-xl border border-slate-800/60 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-5">
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="h-4 w-4 text-cyan-400" />
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          Stack Activo
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Provider */}
        <button
          onClick={() => onNavigate("providers")}
          className="group rounded-lg border border-slate-800/60 bg-slate-900/50 p-4 text-left hover:border-cyan-500/30 transition-colors"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Proveedor</span>
            {providerReady ? (
              <span className="flex items-center gap-1 text-[10px] font-medium text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                CONECTADO
              </span>
            ) : stack.provider ? (
              <span className="flex items-center gap-1 text-[10px] font-medium text-amber-400">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                SIN CREDENCIALES
              </span>
            ) : (
              <span className="flex items-center gap-1 text-[10px] font-medium text-red-400">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                NO CONFIGURADO
              </span>
            )}
          </div>
          {stack.provider ? (
            <div className="flex items-center gap-3">
              <span className="text-2xl">
                {PROVIDER_ICONS[stack.provider.slug] || "🔧"}
              </span>
              <div>
                <p className="font-semibold text-white group-hover:text-cyan-400 transition-colors">
                  {stack.provider.name}
                </p>
                <p className="text-xs text-slate-500 font-mono">{stack.provider.slug}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500">Selecciona un proveedor →</p>
          )}
        </button>

        {/* Default Model */}
        <button
          onClick={() => onNavigate("models")}
          className="group rounded-lg border border-slate-800/60 bg-slate-900/50 p-4 text-left hover:border-cyan-500/30 transition-colors"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Modelo por defecto</span>
            {stack.defaultModel ? (
              <span className="flex items-center gap-1 text-[10px] font-medium text-cyan-400">
                <Sparkles className="h-3 w-3" />
                EN USO
              </span>
            ) : (
              <span className="flex items-center gap-1 text-[10px] font-medium text-red-400">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                SIN MODELO
              </span>
            )}
          </div>
          {stack.defaultModel ? (
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500/30 to-purple-500/30 flex items-center justify-center">
                <Brain className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="min-w-0">
                <p className="font-semibold text-white truncate group-hover:text-cyan-400 transition-colors">
                  {stack.defaultModel.name}
                </p>
                <p className="text-xs text-slate-500 font-mono truncate">
                  {stack.defaultModel.modelId}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500">Agrega y marca un modelo →</p>
          )}
        </button>

        {/* Counts */}
        <div className="rounded-lg border border-slate-800/60 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Recursos activos</span>
            <button
              onClick={() => onNavigate("health")}
              className="text-[10px] font-medium text-slate-500 hover:text-cyan-400 transition-colors flex items-center gap-1"
            >
              Ver salud <ArrowRight className="h-3 w-3" />
            </button>
          </div>
          <div className="flex items-center gap-6">
            <div>
              <p className="text-2xl font-bold text-white">{stack.activeProviderCount}</p>
              <p className="text-xs text-slate-500">Proveedores</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stack.activeModelCount}</p>
              <p className="text-xs text-slate-500">Modelos</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== SETUP GUIDE ====================
function SetupGuide({
  hasProvider,
  hasModel,
  onNavigate,
}: {
  hasProvider: boolean;
  hasModel: boolean;
  onNavigate: (tab: TabId) => void;
}) {
  const steps = [
    {
      done: hasProvider,
      label: "Conecta un proveedor",
      desc: "Configura la API key u OAuth de tu proveedor de IA",
      tab: "providers" as TabId,
    },
    {
      done: hasModel,
      label: "Agrega un modelo",
      desc: "Añade un modelo del catálogo del proveedor",
      tab: "models" as TabId,
    },
    {
      done: false,
      label: "Márcalo como default",
      desc: "El modelo default se usa en todos los análisis",
      tab: "models" as TabId,
    },
  ];

  // If model exists but provider doesn't (edge case), adjust step 3
  if (hasModel) steps[2].done = true;

  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="h-4 w-4 text-cyan-400" />
        <h2 className="text-sm font-semibold text-cyan-300">
          Guía de configuración inicial
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {steps.map((step, i) => (
          <button
            key={i}
            onClick={() => onNavigate(step.tab)}
            className={cn(
              "flex items-start gap-3 rounded-lg border p-3 text-left transition-colors",
              step.done
                ? "border-emerald-500/30 bg-emerald-500/5"
                : "border-slate-700/60 bg-slate-900/40 hover:border-cyan-500/30"
            )}
          >
            {step.done ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <CircleDashed className="h-5 w-5 text-slate-500 shrink-0 mt-0.5" />
            )}
            <div>
              <p className={cn("text-sm font-medium", step.done ? "text-emerald-300" : "text-white")}>
                {i + 1}. {step.label}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">{step.desc}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

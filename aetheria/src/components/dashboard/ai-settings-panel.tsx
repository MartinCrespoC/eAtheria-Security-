"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Loader2,
  Save,
  Brain,
  Cpu,
  DollarSign,
  Coins,
  TrendingUp,
  AlertTriangle,
  KeyRound,
  TestTube,
  CheckCircle2,
  XCircle,
  Eye,
  EyeOff,
} from "lucide-react";

interface CompanyInfo {
  id: string;
  name: string;
  aiProvider: {
    id: string;
    name: string;
    slug: string;
    type: string;
    baseUrl?: string | null;
    hasApiKey?: boolean;
    isOwn?: boolean;
  } | null;
  usingSystemDefault?: boolean;
  aiTokenLimit: number | null;
  aiCostLimit: string | null;
}

const PROVIDER_TEMPLATES = [
  { slug: "openrouter", label: "OpenRouter", needsBaseUrl: false, placeholder: "sk-or-..." },
  { slug: "openai", label: "OpenAI", needsBaseUrl: false, placeholder: "sk-..." },
  { slug: "anthropic", label: "Anthropic", needsBaseUrl: false, placeholder: "sk-ant-..." },
  { slug: "gemini", label: "Google Gemini", needsBaseUrl: false, placeholder: "AIza..." },
  { slug: "deepseek", label: "DeepSeek", needsBaseUrl: false, placeholder: "sk-..." },
  { slug: "custom", label: "Custom (OpenAI-compatible)", needsBaseUrl: true, placeholder: "" },
];

interface ModelInfo {
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
  aiProvider: { id: string; name: string; slug: string } | null;
}

interface UsageData {
  quota: {
    allowed: boolean;
    remaining: number;
    percentUsed: number;
    tokenLimit: number | null;
    tokensUsed: number;
    costLimit: number | null;
    costUsed: number;
    blocked: boolean;
  };
  summary: {
    totalTokens: number;
    totalCost: number;
    tokenLimit: number | null;
    costLimit: number | null;
    percentUsed: number;
    remaining: number;
  };
}

const TASK_TYPES = [
  { key: "sast", label: "SAST Analysis" },
  { key: "sca", label: "SCA Analysis" },
  { key: "dast", label: "DAST Scanning" },
  { key: "pentest", label: "Pentesting" },
  { key: "codefix", label: "Code Fix" },
];

export function AISettingsPanel() {
  const [company, setCompany] = useState<CompanyInfo | null>(null);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [preferences, setPreferences] = useState<Record<string, string>>({});
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Own-provider state
  const [ownTemplate, setOwnTemplate] = useState("openrouter");
  const [ownKey, setOwnKey] = useState("");
  const [ownBaseUrl, setOwnBaseUrl] = useState("");
  const [ownShowKey, setOwnShowKey] = useState(false);
  const [ownBusy, setOwnBusy] = useState<"test" | "save" | null>(null);
  const [ownResult, setOwnResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [savingDefault, setSavingDefault] = useState(false);

  const template = PROVIDER_TEMPLATES.find((t) => t.slug === ownTemplate)!;

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchSettings = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-settings");
      if (res.ok) {
        const data = await res.json();
        setCompany(data.company);
        setModels(data.models || []);
        setPreferences(data.modelPreferences || {});
      }
    } catch {
      showMsg("error", "Failed to load AI settings");
    }
  }, [showMsg]);

  const fetchUsage = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-usage");
      if (res.ok) {
        setUsage(await res.json());
      }
    } catch {
      // Non-critical
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    Promise.all([fetchSettings(), fetchUsage()]);
  }, [fetchSettings, fetchUsage]);

  async function handleOwnProvider(testOnly: boolean) {
    setOwnBusy(testOnly ? "test" : "save");
    setOwnResult(null);
    try {
      const res = await fetch("/api/admin/ai-settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: {
            templateSlug: ownTemplate,
            apiKey: ownKey.trim(),
            baseUrl: template.needsBaseUrl ? ownBaseUrl.trim() : undefined,
            testOnly,
          },
        }),
      });
      const data = await res.json();
      if (testOnly) {
        setOwnResult({ ok: !!data.ok, error: data.error });
      } else if (data.ok) {
        setOwnResult({ ok: true });
        showMsg(
          "success",
          `Proveedor propio configurado (${data.models?.length || 0} modelos descubiertos)`
        );
        await fetchSettings();
      } else {
        setOwnResult({ ok: false, error: data.error });
      }
    } catch {
      setOwnResult({ ok: false, error: "No se pudo contactar al servidor" });
    } finally {
      setOwnBusy(null);
    }
  }

  async function handleDefaultModel(modelDbId: string) {
    setSavingDefault(true);
    try {
      const res = await fetch("/api/admin/ai-settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ defaultModelId: modelDbId }),
      });
      if (res.ok) {
        showMsg("success", "Modelo por defecto actualizado");
        await fetchSettings();
      } else {
        showMsg("error", "No se pudo cambiar el modelo por defecto");
      }
    } finally {
      setSavingDefault(false);
    }
  }

  async function savePreferences() {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/ai-settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ modelPreferences: preferences }),
      });
      if (res.ok) {
        showMsg("success", "Model preferences saved");
      } else {
        showMsg("error", "Failed to save preferences");
      }
    } catch {
      showMsg("error", "Network error");
    }
    setSaving(false);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-text-secondary" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Brain className="h-6 w-6 text-accent" />
          AI Settings
        </h1>
        <p className="text-text-secondary mt-1">
          Configure model preferences and view usage for your organization
        </p>
      </div>

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

      {/* Assigned Provider */}
      <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Cpu className="h-4 w-4 text-accent" />
          <h2 className="text-sm font-medium text-text-primary">Assigned Provider</h2>
        </div>
        {company?.aiProvider ? (
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg flex items-center justify-center bg-gradient-to-br from-cyan-500/20 to-purple-500/20">
              <Brain className="h-5 w-5 text-accent" />
            </div>
            <div>
              <p className="text-sm font-medium text-text-primary">{company.aiProvider.name}</p>
              <p className="text-xs text-text-muted font-mono">
                {company.aiProvider.slug} · {company.aiProvider.type}
              </p>
              {company.usingSystemDefault && (
                <p className="text-xs text-accent mt-0.5">
                  Usando default del sistema — asignado por el administrador
                </p>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-amber-400">
            No provider assigned. Contact your system administrator.
          </p>
        )}
        <p className="text-xs text-text-muted mt-2">
          {company?.aiProvider?.isOwn
            ? "Proveedor propio de tu empresa — independiente del sistema."
            : "Puedes usar el proveedor del sistema o configurar uno propio abajo."}
        </p>
      </div>

      {/* Own provider — each company can bring its own key */}
      <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
        <div className="flex items-center gap-2 mb-1">
          <KeyRound className="h-4 w-4 text-purple-400" />
          <h2 className="text-sm font-medium text-text-primary">Proveedor propio de la empresa</h2>
        </div>
        <p className="text-xs text-text-muted mb-4">
          Conecta tu propia API key. Los modelos se cargan en tiempo real desde el
          proveedor y los análisis de tu empresa usarán esta cuenta (aislada del resto).
          La key se cifra con AES-256-GCM.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-text-secondary block mb-1">Proveedor</label>
            <select
              value={ownTemplate}
              onChange={(e) => { setOwnTemplate(e.target.value); setOwnResult(null); }}
              className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-text-primary text-sm focus:border-cyan-500/50 focus:outline-none"
            >
              {PROVIDER_TEMPLATES.map((t) => (
                <option key={t.slug} value={t.slug}>{t.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">API Key</label>
            <div className="relative">
              <input
                type={ownShowKey ? "text" : "password"}
                value={ownKey}
                onChange={(e) => { setOwnKey(e.target.value); setOwnResult(null); }}
                placeholder={template.placeholder || "sk-..."}
                className="w-full px-3 py-2 pr-9 rounded-lg bg-surface border border-border text-text-primary text-sm font-mono focus:border-cyan-500/50 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setOwnShowKey(!ownShowKey)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {ownShowKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
          {template.needsBaseUrl && (
            <div className="sm:col-span-2">
              <label className="text-xs text-text-secondary block mb-1">Base URL</label>
              <input
                type="text"
                value={ownBaseUrl}
                onChange={(e) => setOwnBaseUrl(e.target.value)}
                placeholder="https://api.tu-proveedor.com/v1"
                className="w-full px-3 py-2 rounded-lg bg-surface border border-border text-text-primary text-sm font-mono focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
          )}
        </div>

        <div className="flex gap-2 mt-3">
          <button
            onClick={() => handleOwnProvider(true)}
            disabled={!!ownBusy || !ownKey.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-surface text-text-secondary border border-border hover:text-text-primary transition-colors disabled:opacity-50"
          >
            {ownBusy === "test" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <TestTube className="h-3.5 w-3.5" />}
            Probar conexión
          </button>
          <button
            onClick={() => handleOwnProvider(false)}
            disabled={!!ownBusy || !ownKey.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors disabled:opacity-50"
          >
            {ownBusy === "save" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Guardar y activar
          </button>
        </div>

        {ownResult && (
          <div className={`mt-3 rounded-lg px-3 py-2 text-xs flex items-center gap-2 ${
            ownResult.ok
              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border border-red-500/30 text-red-400"
          }`}>
            {ownResult.ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
            {ownResult.ok ? "Conexión correcta" : ownResult.error || "Error de conexión"}
          </div>
        )}
      </div>

      {/* Usage Stats */}
      {usage && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Token Usage */}
          <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Coins className="h-4 w-4 text-accent" />
                <h3 className="text-sm font-medium text-text-primary">Token Usage (This Month)</h3>
              </div>
            </div>
            <p className="text-2xl font-bold text-text-primary">
              {usage.summary.totalTokens.toLocaleString()}
            </p>
            <p className="text-xs text-text-muted mt-1">
              {usage.summary.tokenLimit
                ? `of ${usage.summary.tokenLimit.toLocaleString()} limit`
                : "Unlimited"}
            </p>
            {usage.summary.tokenLimit && (
              <div className="mt-3">
                <div className="h-2 rounded-full bg-surface overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      usage.summary.percentUsed >= 100
                        ? "bg-red-500"
                        : usage.summary.percentUsed >= 80
                        ? "bg-amber-500"
                        : "bg-cyan-500"
                    }`}
                    style={{ width: `${Math.min(100, usage.summary.percentUsed)}%` }}
                  />
                </div>
                <p className="text-xs text-text-muted mt-1">
                  {usage.summary.percentUsed.toFixed(1)}% used
                </p>
              </div>
            )}
          </div>

          {/* Cost Usage */}
          <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <DollarSign className="h-4 w-4 text-emerald-400" />
                <h3 className="text-sm font-medium text-text-primary">Cost (This Month)</h3>
              </div>
            </div>
            <p className="text-2xl font-bold text-text-primary">
              ${usage.summary.totalCost.toFixed(2)}
            </p>
            <p className="text-xs text-text-muted mt-1">
              {usage.summary.costLimit
                ? `of $${usage.summary.costLimit.toFixed(2)} limit`
                : "Unlimited"}
            </p>
            {usage.summary.costLimit && usage.quota && (
              <div className="mt-3">
                <div className="h-2 rounded-full bg-surface overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      usage.summary.percentUsed >= 100
                        ? "bg-red-500"
                        : usage.summary.percentUsed >= 80
                        ? "bg-amber-500"
                        : "bg-emerald-500"
                    }`}
                    style={{ width: `${Math.min(100, usage.summary.percentUsed)}%` }}
                  />
                </div>
                <p className="text-xs text-text-muted mt-1">
                  {usage.summary.percentUsed.toFixed(1)}% used
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Quota Warning */}
      {usage?.quota?.blocked && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">AI Usage Limit Reached</p>
            <p className="text-xs text-red-300/80 mt-1">
              Your organization has reached its AI usage limit. AI features are blocked until limits are increased or the next billing cycle.
            </p>
          </div>
        </div>
      )}

      {/* Model Preferences */}
      <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="h-4 w-4 text-purple-400" />
          <h2 className="text-sm font-medium text-text-primary">Model Preferences</h2>
        </div>

        {models.length === 0 ? (
          <p className="text-sm text-text-muted">
            No models available. Contact your administrator to configure AI models.
          </p>
        ) : (
          <div className="space-y-4">
            {TASK_TYPES.map((task) => (
              <div key={task.key} className="flex items-center justify-between gap-4">
                <label className="text-sm text-text-primary flex-shrink-0 w-40">{task.label}</label>
                <select
                  value={preferences[task.key] || ""}
                  onChange={(e) =>
                    setPreferences((prev) => ({ ...prev, [task.key]: e.target.value }))
                  }
                  className="flex-1 px-3 py-2 rounded-lg bg-surface border border-border text-text-primary text-sm focus:border-cyan-500/50 focus:outline-none"
                >
                  <option value="">— Default —</option>
                  {models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.modelId})
                    </option>
                  ))}
                </select>
              </div>
            ))}

            <div className="flex justify-end pt-2">
              <button
                onClick={savePreferences}
                disabled={saving}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-cyan-500/10 text-accent border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
              >
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                Save Preferences
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Available Models */}
      {models.length > 0 && (
        <div className="rounded-xl border border-border bg-card backdrop-blur-xl p-5">
          <h2 className="text-sm font-medium text-text-primary mb-1">Available Models</h2>
          <p className="text-xs text-text-muted mb-3">
            Marca uno como por defecto — los análisis de tu empresa lo usarán.
          </p>
          <div className="space-y-2">
            {models.map((m) => (
              <div key={m.id} className="flex items-center justify-between py-2 border-b border-border last:border-0">
                <div>
                  <p className="text-sm text-text-primary">{m.name}</p>
                  <p className="text-xs text-text-muted font-mono">{m.modelId}</p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="text-xs text-right text-text-secondary">
                    <p>In: ${Number(m.inputTokenCost).toFixed(2)}/M</p>
                    <p>Out: ${Number(m.outputTokenCost).toFixed(2)}/M</p>
                  </div>
                  <button
                    onClick={() => handleDefaultModel(m.id)}
                    disabled={savingDefault}
                    className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide border transition-colors ${
                      m.isDefault
                        ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/40"
                        : "bg-surface text-text-muted border-border hover:text-text-primary"
                    }`}
                  >
                    {m.isDefault ? "Por defecto" : "Usar"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

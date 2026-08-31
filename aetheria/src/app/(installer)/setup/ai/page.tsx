"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sparkles,
  KeyRound,
  Loader2,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Eye,
  EyeOff,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Provider {
  id: string;
  slug: string;
  name: string;
  type: string;
  baseUrl: string | null;
  isActive: boolean;
  hasApiKey: boolean;
  configured: boolean;
  modelCount: number;
}

export default function AISetupPage() {
  const router = useRouter();

  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [showKey, setShowKey] = useState(false);

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [defaultModel, setDefaultModel] = useState<string | null>(null);
  const [models, setModels] = useState<{ id: string; name: string; modelId: string; isDefault: boolean }[]>([]);
  const [pickingModel, setPickingModel] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadProviders = useCallback(async () => {
    try {
      const res = await fetch("/api/setup/ai-provider");
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
        // Pre-select an already-configured provider, if any.
        const configured = (data.providers || []).find((p: Provider) => p.configured);
        if (configured) {
          setSelectedId(configured.id);
          setSaved(true);
        }
      } else {
        setLoadError("No se pudieron cargar los proveedores de IA.");
      }
    } catch {
      setLoadError("No se pudo conectar con el servidor.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  const selected = providers.find((p) => p.id === selectedId) || null;
  // Offer a custom base URL for OpenAI-compatible / custom endpoints.
  const showBaseUrl =
    selected?.type === "openai-compatible" || selected?.slug === "custom";

  function selectProvider(p: Provider) {
    setSelectedId(p.id);
    setApiKey("");
    setBaseUrl(p.baseUrl || "");
    setTestResult(null);
    setSaved(p.configured);
    setModels([]);
    setError(null);
  }

  async function handlePickDefaultModel(modelId: string, modelName: string) {
    if (!selected || !apiKey.trim()) return;
    setPickingModel(true);
    try {
      const res = await fetch("/api/setup/ai-provider", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          providerId: selected.id,
          apiKey: apiKey.trim(),
          baseUrl: showBaseUrl ? baseUrl.trim() : undefined,
          defaultModelId: modelId,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setDefaultModel(data.defaultModel || modelName);
        setModels((prev) => prev.map((m) => ({ ...m, isDefault: m.id === modelId })));
      }
    } catch { /* keep previous default */ } finally {
      setPickingModel(false);
    }
  }

  async function handleTest() {
    if (!selected || !apiKey.trim()) return;
    setTesting(true);
    setTestResult(null);
    setError(null);
    try {
      const res = await fetch("/api/setup/ai-provider", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          providerId: selected.id,
          apiKey: apiKey.trim(),
          baseUrl: showBaseUrl ? baseUrl.trim() : undefined,
          testOnly: true,
        }),
      });
      const data = await res.json();
      setTestResult({ ok: !!data.ok, error: data.error });
    } catch {
      setTestResult({ ok: false, error: "No se pudo contactar al servidor." });
    } finally {
      setTesting(false);
    }
  }

  async function handleSave() {
    if (!selected || !apiKey.trim()) return;
    setSaving(true);
    setError(null);
    setTestResult(null);
    try {
      const res = await fetch("/api/setup/ai-provider", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          providerId: selected.id,
          apiKey: apiKey.trim(),
          baseUrl: showBaseUrl ? baseUrl.trim() : undefined,
        }),
      });
      const data = await res.json();
      if (data.success) {
        setSaved(true);
        setDefaultModel(data.defaultModel || null);
        setModels(data.models || []);
        setTestResult(data.test || null);
      } else {
        setError(data.error || "No se pudo guardar la API key.");
      }
    } catch {
      setError("No se pudo contactar al servidor.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
      </div>
    );
  }

  return (
    <div>
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-purple-500/10 border border-purple-500/30 mb-3">
          <Sparkles className="w-7 h-7 text-purple-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-1">
          Conecta tu <span className="gradient-text">IA</span>
        </h2>
        <p className="text-sm text-slate-400">
          EATHERIA usa un modelo de IA para validar hallazgos y generar
          correcciones. Configura tu proveedor para que los análisis funcionen
          desde el primer momento.
        </p>
      </div>

      {loadError ? (
        <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 mb-4">
          <p className="text-sm text-red-400">{loadError}</p>
        </div>
      ) : (
        <>
          {/* Provider selection */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-5 max-h-56 overflow-y-auto pr-1">
            {providers.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => selectProvider(p)}
                className={cn(
                  "relative p-3 rounded-lg border-2 text-left transition-all",
                  selectedId === p.id
                    ? "border-purple-500 bg-purple-500/10"
                    : "border-slate-700/50 bg-slate-900/40 hover:border-slate-600"
                )}
              >
                <div
                  className={cn(
                    "text-sm font-semibold truncate",
                    selectedId === p.id ? "text-purple-300" : "text-slate-200"
                  )}
                >
                  {p.name}
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  {p.modelCount > 0
                    ? `${p.modelCount} modelo${p.modelCount === 1 ? "" : "s"}`
                    : "Sin modelos"}
                </div>
                {p.configured && (
                  <CheckCircle2 className="absolute top-2 right-2 w-4 h-4 text-green-400" />
                )}
              </button>
            ))}
          </div>

          {/* Key form */}
          {selected && (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="apiKey">API Key — {selected.name}</Label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <Input
                    id="apiKey"
                    type={showKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      setTestResult(null);
                      setSaved(selected.configured);
                    }}
                    placeholder="Pega tu API key aquí"
                    disabled={saving}
                    className="pl-9 pr-10 font-mono text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
                  >
                    {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-xs text-slate-500">
                  Se cifra con AES-256-GCM antes de guardarse. Nunca se almacena
                  en texto plano.
                </p>
              </div>

              {showBaseUrl && (
                <div className="space-y-2">
                  <Label htmlFor="baseUrl">Base URL (opcional)</Label>
                  <Input
                    id="baseUrl"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    placeholder={selected.baseUrl || "https://api.ejemplo.com/v1"}
                    disabled={saving}
                    className="font-mono text-xs"
                  />
                </div>
              )}

              {/* Test / save actions */}
              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={handleTest}
                  disabled={testing || saving || !apiKey.trim()}
                >
                  {testing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Probando...
                    </>
                  ) : (
                    "Probar conexión"
                  )}
                </Button>
                <Button
                  onClick={handleSave}
                  disabled={saving || testing || !apiKey.trim()}
                  className="flex-1"
                >
                  {saving ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Guardando...
                    </>
                  ) : (
                    <>
                      Guardar y activar
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </Button>
              </div>

              {/* Test result */}
              {testResult && (
                <div
                  className={cn(
                    "p-3 rounded-lg border flex items-start gap-3",
                    testResult.ok
                      ? "border-green-500/30 bg-green-500/10"
                      : "border-red-500/30 bg-red-500/10"
                  )}
                >
                  {testResult.ok ? (
                    <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                  )}
                  <div className="text-sm">
                    {testResult.ok ? (
                      <span className="text-green-400">
                        ¡Conexión correcta!{defaultModel ? ` Modelo por defecto: ${defaultModel}.` : ""}
                      </span>
                    ) : (
                      <span className="text-red-400">{testResult.error}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Saved confirmation */}
              {saved && !testResult && (
                <div className="p-3 rounded-lg border border-green-500/30 bg-green-500/10 flex items-start gap-3">
                  <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                  <span className="text-sm text-green-400">
                    Proveedor configurado. Los análisis usarán {selected.name}.
                  </span>
                </div>
              )}

              {/* Discovered models — pick the default */}
              {saved && models.length > 0 && (
                <div className="space-y-2">
                  <Label>Modelo por defecto ({models.length} disponibles)</Label>
                  <div className="max-h-44 overflow-y-auto rounded-lg border border-slate-700/50 divide-y divide-slate-800">
                    {models.map((m) => (
                      <button
                        key={m.id}
                        type="button"
                        disabled={pickingModel}
                        onClick={() => handlePickDefaultModel(m.id, m.name)}
                        className={cn(
                          "w-full flex items-center justify-between px-3 py-2 text-left text-xs transition-colors",
                          defaultModel === m.name
                            ? "bg-purple-500/10 text-purple-300"
                            : "text-slate-300 hover:bg-slate-800/50"
                        )}
                      >
                        <span className="truncate">
                          <span className="font-medium">{m.name}</span>
                          <span className="text-slate-500 ml-2 font-mono">{m.modelId}</span>
                        </span>
                        {defaultModel === m.name && (
                          <CheckCircle2 className="w-4 h-4 text-purple-400 flex-shrink-0" />
                        )}
                      </button>
                    ))}
                  </div>
                  <p className="text-[11px] text-slate-500">
                    Cargados en tiempo real desde la API de {selected.name}. Puedes
                    cambiarlo luego en Admin → Configuración IA.
                  </p>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {error && (
        <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Info note */}
      <div className="mt-4 p-3 rounded-lg border border-slate-700/50 bg-slate-900/40">
        <p className="text-xs text-slate-400 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-amber-400" />
          Puedes omitir este paso y configurar la IA más tarde en{" "}
          <span className="font-mono text-slate-300">Admin → Configuración IA</span>,
          pero los análisis no funcionarán hasta que haya una clave activa.
        </p>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between mt-6">
        <Button variant="ghost" onClick={() => router.push("/setup/admin")}>
          <ArrowLeft className="w-4 h-4" />
          Atrás
        </Button>

        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={() => router.push("/setup/whatsapp")}>
            Omitir
          </Button>
          <Button onClick={() => router.push("/setup/whatsapp")} disabled={!saved}>
            Continuar
            <ArrowRight className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import {
  Brain,
  Plug,
  PlugZap,
  Trash2,
  Power,
  PowerOff,
  Key,
  TestTube,
  Loader2,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Copy,
  RefreshCw,
} from "lucide-react";

interface AIProvider {
  id: string;
  slug: string;
  name: string;
  type: string;
  baseUrl: string | null;
  authType: string;
  isActive: boolean;
  hasApiKey: boolean;
  config: Record<string, unknown> | null;
  _count: { models: number };
}

interface OAuthFlowState {
  providerId: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  status: "pending" | "connected" | "expired" | "denied" | "error";
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

export function AIProvidersManager() {
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [configModal, setConfigModal] = useState<AIProvider | null>(null);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [baseUrlInput, setBaseUrlInput] = useState("");
  const [serviceAccountInput, setServiceAccountInput] = useState("");
  const [binaryPathInput, setBinaryPathInput] = useState("");
  const [oauthFlow, setOauthFlow] = useState<OAuthFlowState | null>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchProviders = useCallback(async () => {
    const res = await fetch("/api/admin/ai-providers");
    if (res.ok) setProviders(await res.json());
  }, []);

  useEffect(() => {
    let active = true;
    fetchProviders().finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [fetchProviders]);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  async function toggleActive(id: string, currentActive: boolean) {
    setActionLoading(id);
    const res = await fetch(`/api/admin/ai-providers/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: !currentActive }),
    });
    if (res.ok) {
      showMsg("success", currentActive ? "Provider desactivado" : "Provider activado");
      await fetchProviders();
    } else {
      showMsg("error", "Error al actualizar");
    }
    setActionLoading(null);
  }

  async function testConnection(id: string) {
    setActionLoading(`test-${id}`);
    try {
      const res = await fetch(`/api/admin/ai-providers/${id}/test`, { method: "POST" });
      const data = await res.json();
      if (data.ok) {
        showMsg("success", "¡Conexión exitosa!");
      } else {
        showMsg("error", data.error || "Conexión fallida");
      }
    } catch {
      showMsg("error", "Error de conexión");
    }
    setActionLoading(null);
  }

  async function deleteProvider(id: string) {
    if (!confirm("¿Eliminar este provider?")) return;
    setActionLoading(id);
    const res = await fetch(`/api/admin/ai-providers/${id}`, { method: "DELETE" });
    if (res.ok) {
      showMsg("success", "Provider eliminado");
      await fetchProviders();
    } else {
      const err = await res.json();
      showMsg("error", err.error || "Error al eliminar");
    }
    setActionLoading(null);
  }

  async function saveConfig() {
    if (!configModal) return;
    setActionLoading(`config-${configModal.id}`);

    const body: Record<string, unknown> = {};
    if (apiKeyInput) body.apiKey = apiKeyInput;
    if (baseUrlInput !== (configModal.baseUrl || "")) body.baseUrl = baseUrlInput;
    if (configModal.authType === "service_account" && serviceAccountInput) {
      body.serviceAccountJson = serviceAccountInput;
    }
    if ((configModal.authType === "none" || configModal.type === "cli-bridge") && binaryPathInput) {
      body.config = { ...(configModal.config || {}), binaryPath: binaryPathInput };
    }

    const res = await fetch(`/api/admin/ai-providers/${configModal.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (res.ok) {
      showMsg("success", "Configuración guardada");
      setConfigModal(null);
      setApiKeyInput("");
      setBaseUrlInput("");
      setServiceAccountInput("");
      setBinaryPathInput("");
      await fetchProviders();
    } else {
      showMsg("error", "Error al guardar");
    }
    setActionLoading(null);
  }

  async function startOAuth(provider: AIProvider) {
    setActionLoading(`oauth-${provider.id}`);
    try {
      const res = await fetch(`/api/admin/ai-providers/${provider.id}/oauth/start`, {
        method: "POST",
      });
      const data = await res.json();

      if (data.userCode) {
        setOauthFlow({
          providerId: provider.id,
          userCode: data.userCode,
          verificationUri: data.verificationUri,
          expiresIn: data.expiresIn,
          status: "pending",
        });

        // Start polling
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(async () => {
          const pollRes = await fetch(`/api/admin/ai-providers/${provider.id}/oauth/status`);
          const pollData = await pollRes.json();

          if (pollData.status === "connected") {
            if (pollRef.current) clearInterval(pollRef.current);
            setOauthFlow((prev) => prev ? { ...prev, status: "connected" } : null);
            showMsg("success", "¡Conectado exitosamente!");
            await fetchProviders();
          } else if (pollData.status === "expired" || pollData.status === "denied" || pollData.status === "error") {
            if (pollRef.current) clearInterval(pollRef.current);
            setOauthFlow((prev) => prev ? { ...prev, status: pollData.status } : null);
            showMsg("error", pollData.message || "Error en autorización");
          }
        }, (data.interval || 5) * 1000);
      } else {
        showMsg("error", data.error || "Error al iniciar OAuth");
      }
    } catch {
      showMsg("error", "Error de conexión");
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
      <div>
        <h1 className="text-2xl font-bold text-white">Proveedores de IA</h1>
        <p className="text-slate-400 mt-1">
          Configura API keys, conecta OAuth y gestiona los proveedores de modelos de IA
        </p>
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

      {/* OAuth Flow Modal */}
      {oauthFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl">
            {oauthFlow.status === "pending" && (
              <>
                <h3 className="text-xl font-bold text-white mb-4 text-center">Autorizar acceso</h3>
                <p className="text-slate-400 text-sm text-center mb-6">
                  Abre el siguiente enlace e ingresa el código:
                </p>
                <div className="bg-slate-800 rounded-xl p-6 text-center mb-6">
                  <p className="text-3xl font-mono font-bold text-cyan-400 tracking-widest">
                    {oauthFlow.userCode}
                  </p>
                </div>
                <a
                  href={oauthFlow.verificationUri}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-center gap-2 w-full px-4 py-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm font-medium mb-4"
                >
                  <ExternalLink className="h-4 w-4" />
                  Abrir {oauthFlow.verificationUri}
                </a>
                <button
                  onClick={() => navigator.clipboard.writeText(oauthFlow.userCode)}
                  className="flex items-center justify-center gap-2 w-full px-4 py-2 rounded-lg text-slate-400 hover:text-white transition-colors text-xs"
                >
                  <Copy className="h-3 w-3" /> Copiar código
                </button>
                <div className="flex items-center justify-center gap-2 mt-4 text-xs text-slate-500">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Esperando autorización...
                </div>
              </>
            )}
            {oauthFlow.status === "connected" && (
              <div className="text-center">
                <CheckCircle2 className="h-16 w-16 text-emerald-400 mx-auto mb-4" />
                <h3 className="text-xl font-bold text-white mb-2">¡Conectado!</h3>
                <p className="text-slate-400 text-sm">El provider fue autorizado exitosamente.</p>
              </div>
            )}
            {(oauthFlow.status === "expired" || oauthFlow.status === "denied" || oauthFlow.status === "error") && (
              <div className="text-center">
                <XCircle className="h-16 w-16 text-red-400 mx-auto mb-4" />
                <h3 className="text-xl font-bold text-white mb-2">Error</h3>
                <p className="text-slate-400 text-sm">
                  {oauthFlow.status === "expired" && "El código expiró. Intenta de nuevo."}
                  {oauthFlow.status === "denied" && "La autorización fue denegada."}
                  {oauthFlow.status === "error" && "Ocurrió un error."}
                </p>
              </div>
            )}
            <button
              onClick={() => {
                if (pollRef.current) clearInterval(pollRef.current);
                setOauthFlow(null);
              }}
              className="mt-6 w-full px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white transition-colors text-sm"
            >
              Cerrar
            </button>
          </div>
        </div>
      )}

      {/* Config Modal */}
      {configModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl">
            <h3 className="text-xl font-bold text-white mb-1">
              Configurar {configModal.name}
            </h3>
            <p className="text-slate-500 text-xs mb-6 font-mono">{configModal.slug}</p>

            <div className="space-y-4">
              {configModal.authType === "service_account" ? (
                <div>
                  <label className="text-sm text-slate-400 block mb-1.5">Service Account JSON</label>
                  <textarea
                    value={serviceAccountInput}
                    onChange={(e) => setServiceAccountInput(e.target.value)}
                    placeholder='{"type":"service_account","project_id":"...","private_key":"..."}'
                    rows={6}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white text-xs font-mono placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none resize-y"
                  />
                  <p className="text-xs text-slate-600 mt-1">Pega el JSON completo de la cuenta de servicio de Google Cloud</p>
                </div>
              ) : configModal.authType === "none" || configModal.type === "cli-bridge" ? (
                <div>
                  <label className="text-sm text-slate-400 block mb-1.5">Ruta del binario (opcional)</label>
                  <input
                    type="text"
                    value={binaryPathInput}
                    onChange={(e) => setBinaryPathInput(e.target.value)}
                    placeholder={(configModal.config as Record<string, unknown>)?.binary as string || "grok"}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm font-mono placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  />
                  <p className="text-xs text-slate-600 mt-1">
                    Este provider usa un CLI local. No requiere API key. Asegúrate de que el binario esté en el PATH.
                  </p>
                </div>
              ) : (
                <div>
                  <label className="text-sm text-slate-400 block mb-1.5">API Key</label>
                  <input
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder={configModal.hasApiKey ? "••••••••  (dejar vacío para mantener)" : "sk-..."}
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  />
                </div>
              )}
              {configModal.authType !== "none" && configModal.type !== "cli-bridge" && (
                <div>
                  <label className="text-sm text-slate-400 block mb-1.5">Base URL (opcional)</label>
                  <input
                    type="text"
                    value={baseUrlInput}
                    onChange={(e) => setBaseUrlInput(e.target.value)}
                    placeholder="https://api.example.com/v1"
                    className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                  />
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => { setConfigModal(null); setApiKeyInput(""); setBaseUrlInput(""); setServiceAccountInput(""); setBinaryPathInput(""); }}
                className="flex-1 px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white transition-colors text-sm"
              >
                Cancelar
              </button>
              <button
                onClick={saveConfig}
                disabled={actionLoading === `config-${configModal.id}`}
                className="flex-1 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm font-medium"
              >
                {actionLoading === `config-${configModal.id}` ? (
                  <Loader2 className="h-4 w-4 animate-spin mx-auto" />
                ) : "Guardar"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Provider Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {providers.map((provider) => (
          <div
            key={provider.id}
            className={`rounded-xl border p-5 transition-all ${
              provider.isActive
                ? "border-slate-700/60 bg-slate-900/50"
                : "border-slate-800/30 bg-slate-900/20 opacity-60"
            }`}
          >
            {/* Header */}
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-lg flex items-center justify-center bg-gradient-to-br from-slate-700/50 to-slate-800/50 text-xl">
                  {PROVIDER_ICONS[provider.slug] || <Brain className="h-5 w-5 text-violet-400" />}
                </div>
                <div>
                  <h3 className="font-semibold text-white">{provider.name}</h3>
                  <p className="text-xs text-slate-500 font-mono">{provider.slug}</p>
                </div>
              </div>
              <div className="flex gap-1.5">
                {provider.isActive ? (
                  <Badge variant="success">Activo</Badge>
                ) : (
                  <Badge variant="default">Inactivo</Badge>
                )}
              </div>
            </div>

            {/* Info */}
            <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-slate-500">Tipo:</span>{" "}
                <span className="text-slate-300">{provider.type}</span>
              </div>
              <div>
                <span className="text-slate-500">Auth:</span>{" "}
                <span className="text-slate-300">{provider.authType}</span>
              </div>
              <div>
                <span className="text-slate-500">Modelos:</span>{" "}
                <span className="text-white font-medium">{provider._count.models}</span>
              </div>
              <div>
                <span className="text-slate-500">Key:</span>{" "}
                <span className={provider.hasApiKey || provider.authType === "none" || (provider.config as Record<string,unknown>)?.hasToken ? "text-emerald-400" : "text-amber-400"}>
                  {provider.authType === "none" ? "✓ CLI local" : provider.hasApiKey || (provider.config as Record<string,unknown>)?.hasToken ? "✓ configurada" : "✗ sin key"}
                </span>
              </div>
            </div>

            {/* Actions */}
            <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center gap-2 flex-wrap">
              {provider.authType === "oauth" ? (
                <button
                  onClick={() => startOAuth(provider)}
                  disabled={!!actionLoading}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors"
                >
                  {actionLoading === `oauth-${provider.id}` ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <PlugZap className="h-3 w-3" />
                  )}
                  Conectar
                </button>
              ) : (
                <button
                  onClick={() => {
                    setConfigModal(provider);
                    setBaseUrlInput(provider.baseUrl || "");
                  }}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors"
                >
                  <Key className="h-3 w-3" />
                  Configurar
                </button>
              )}

              <button
                onClick={() => testConnection(provider.id)}
                disabled={actionLoading === `test-${provider.id}`}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-800/40 text-slate-400 border border-slate-700/60 hover:text-white transition-colors"
              >
                {actionLoading === `test-${provider.id}` ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <TestTube className="h-3 w-3" />
                )}
                Test
              </button>

              <button
                onClick={() => toggleActive(provider.id, provider.isActive)}
                disabled={!!actionLoading}
                className={`flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium border transition-colors ${
                  provider.isActive
                    ? "bg-slate-800/40 text-slate-400 border-slate-700/60 hover:text-red-400"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20"
                }`}
              >
                {provider.isActive ? <PowerOff className="h-3 w-3" /> : <Power className="h-3 w-3" />}
                {provider.isActive ? "Off" : "On"}
              </button>

              <button
                onClick={() => deleteProvider(provider.id)}
                disabled={!!actionLoading}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-colors ml-auto"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {providers.length === 0 && (
        <div className="text-center py-12">
          <Plug className="h-12 w-12 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400">No hay providers configurados.</p>
          <p className="text-slate-500 text-sm mt-1">Ejecuta el seed para inicializar los providers.</p>
          <div className="mt-4 text-xs font-mono text-slate-600 bg-slate-800/50 rounded-lg px-4 py-2 inline-block">
            npm run db:seed
          </div>
        </div>
      )}

      {/* Help */}
      <div className="rounded-xl border border-slate-800/60 bg-slate-900/30 p-5">
        <div className="flex items-center gap-2 mb-3">
          <RefreshCw className="h-4 w-4 text-slate-500" />
          <h3 className="text-sm font-medium text-slate-300">¿Cómo funciona?</h3>
        </div>
        <ol className="text-xs text-slate-500 space-y-1.5 list-decimal list-inside">
          <li>Configura la API key o conecta OAuth del provider</li>
          <li>Usa &quot;Test&quot; para verificar la conexión</li>
          <li>Activa el provider con el botón On/Off</li>
          <li>Ve a &quot;Modelos de IA&quot; para agregar modelos de ese provider</li>
        </ol>
      </div>
    </div>
  );
}

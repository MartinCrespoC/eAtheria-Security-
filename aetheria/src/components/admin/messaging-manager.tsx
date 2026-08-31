"use client";

import { useState, useEffect } from "react";
import { MessageSquare, Plus, Trash2, Send, ToggleLeft, ToggleRight } from "lucide-react";
import { WhatsAppWebPanel } from "@/components/admin/whatsapp-web-panel";

interface MessagingChannel {
  id: string;
  platform: string;
  name: string;
  isActive: boolean;
  config: Record<string, unknown>;
  createdAt: string;
}

export function MessagingManager() {
  const [channels, setChannels] = useState<MessagingChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [testChatId, setTestChatId] = useState<Record<string, string>>({});
  const [form, setForm] = useState({
    platform: "telegram",
    name: "",
    chatId: "",
    botToken: "",
    phoneNumberId: "",
    accessToken: "",
    appSecret: "",
    webhookVerifyToken: "",
  });

  useEffect(() => {
    fetchChannels();
  }, []);

  async function fetchChannels() {
    try {
      const res = await fetch("/api/admin/messaging");
      const data = await res.json();
      setChannels(data.channels || []);
    } catch (error) {
      console.error("Error fetching channels:", error);
    } finally {
      setLoading(false);
    }
  }

  async function createChannel() {
    const config: Record<string, unknown> = { chatId: form.chatId };
    if (form.platform === "telegram") {
      config.botToken = form.botToken;
    } else if (form.platform === "whatsapp") {
      config.phoneNumberId = form.phoneNumberId;
      config.accessToken = form.accessToken;
      if (form.appSecret) config.appSecret = form.appSecret;
      if (form.webhookVerifyToken) config.webhookVerifyToken = form.webhookVerifyToken;
    }
    // whatsapp_web: only needs chatId — credentials live in the persisted session.

    try {
      const res = await fetch("/api/admin/messaging", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          platform: form.platform,
          name: form.name,
          config,
          isActive: false,
        }),
      });
      if (res.ok) {
        setShowForm(false);
        setForm({ platform: "telegram", name: "", chatId: "", botToken: "", phoneNumberId: "", accessToken: "", appSecret: "", webhookVerifyToken: "" });
        fetchChannels();
      }
    } catch (error) {
      console.error("Error creating channel:", error);
    }
  }

  async function toggleActive(id: string, isActive: boolean) {
    await fetch(`/api/admin/messaging/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isActive: !isActive }),
    });
    fetchChannels();
  }

  async function deleteChannel(id: string) {
    if (!confirm("¿Eliminar este canal de mensajería?")) return;
    await fetch(`/api/admin/messaging/${id}`, { method: "DELETE" });
    fetchChannels();
  }

  async function sendTest(id: string) {
    const chatId = testChatId[id];
    if (!chatId) return;
    const res = await fetch(`/api/admin/messaging/${id}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chatId }),
    });
    const data = await res.json();
    alert(data.success ? "✅ Mensaje de prueba enviado" : `❌ Error: ${data.error}`);
  }

  if (loading) return <div className="text-slate-400">Cargando...</div>;

  return (
    <div className="space-y-6">
      {/* Webhook URLs info */}
      <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-2">URLs de Webhook</h3>
        <div className="space-y-1 text-xs font-mono text-cyan-400">
          <p>Telegram: {typeof window !== "undefined" ? window.location.origin : ""}/api/webhooks/telegram</p>
          <p>WhatsApp: {typeof window !== "undefined" ? window.location.origin : ""}/api/webhooks/whatsapp</p>
        </div>
      </div>

      {/* WhatsApp Web (QR) connection */}
      <WhatsAppWebPanel />

      {/* Create button */}
      <button
        onClick={() => setShowForm(!showForm)}
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-colors"
      >
        <Plus className="h-4 w-4" /> Nuevo Canal
      </button>

      {/* Create form */}
      {showForm && (
        <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Plataforma</label>
              <select
                value={form.platform}
                onChange={(e) => setForm({ ...form, platform: e.target.value })}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm"
              >
                <option value="telegram">Telegram</option>
                <option value="whatsapp">WhatsApp (Cloud API)</option>
                <option value="whatsapp_web">WhatsApp Web (QR)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Nombre</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Mi Bot de Telegram"
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm"
              />
            </div>
          </div>

          <div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Chat ID / Número destino</label>
              <input
                value={form.chatId}
                onChange={(e) => setForm({ ...form, chatId: e.target.value })}
                placeholder={form.platform === "telegram" ? "123456789" : "34600000000"}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
              />
            </div>
          </div>

          {form.platform === "telegram" ? (
            <div>
              <label className="block text-sm text-slate-400 mb-1">Bot Token</label>
              <input
                value={form.botToken}
                onChange={(e) => setForm({ ...form, botToken: e.target.value })}
                placeholder="123456:ABC-DEF..."
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
              />
            </div>
          ) : form.platform === "whatsapp" ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Phone Number ID</label>
                  <input
                    value={form.phoneNumberId}
                    onChange={(e) => setForm({ ...form, phoneNumberId: e.target.value })}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Access Token</label>
                  <input
                    value={form.accessToken}
                    onChange={(e) => setForm({ ...form, accessToken: e.target.value })}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">App Secret (opcional)</label>
                  <input
                    value={form.appSecret}
                    onChange={(e) => setForm({ ...form, appSecret: e.target.value })}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Verify Token (opcional)</label>
                  <input
                    value={form.webhookVerifyToken}
                    onChange={(e) => setForm({ ...form, webhookVerifyToken: e.target.value })}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white text-sm font-mono"
                  />
                </div>
              </div>
            </div>
          ) : (
            <div className="p-3 rounded-lg border border-green-500/30 bg-green-500/10">
              <p className="text-xs text-green-300">
                WhatsApp Web usa la sesión vinculada por QR (panel superior). Solo
                indica el número destino en “Chat ID / Número destino”. Asegúrate de
                que la sesión esté <span className="font-semibold">Conectada</span> antes de activar el canal.
              </p>
            </div>
          )}

          <button
            onClick={createChannel}
            disabled={!form.name}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-medium"
          >
            Crear Canal
          </button>
        </div>
      )}

      {/* Channel list */}
      {channels.length === 0 ? (
        <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-12 text-center">
          <MessageSquare className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">Sin canales de mensajería configurados</p>
          <p className="text-slate-500 text-sm mt-1">Crea un canal para enviar notificaciones por Telegram o WhatsApp</p>
        </div>
      ) : (
        <div className="space-y-4">
          {channels.map((ch) => (
            <div key={ch.id} className="rounded-xl border border-slate-800/60 bg-slate-900/40 p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${ch.platform === "telegram" ? "bg-blue-500/20 text-blue-400" : ch.platform === "whatsapp_web" ? "bg-emerald-500/20 text-emerald-400" : "bg-green-500/20 text-green-400"}`}>
                    {ch.platform === "telegram" ? "Telegram" : ch.platform === "whatsapp_web" ? "WhatsApp Web" : "WhatsApp"}
                  </span>
                  <span className="text-white font-medium">{ch.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => toggleActive(ch.id, ch.isActive)} className="text-slate-400 hover:text-white">
                    {ch.isActive ? <ToggleRight className="h-5 w-5 text-green-400" /> : <ToggleLeft className="h-5 w-5" />}
                  </button>
                  <button onClick={() => deleteChannel(ch.id)} className="text-slate-400 hover:text-red-400">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Test message */}
              <div className="flex items-center gap-2 mt-3">
                <input
                  value={testChatId[ch.id] || ""}
                  onChange={(e) => setTestChatId({ ...testChatId, [ch.id]: e.target.value })}
                  placeholder={ch.platform === "telegram" ? "Chat ID (ej: 123456789)" : "Número (ej: 34600000000)"}
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-white text-xs font-mono"
                />
                <button
                  onClick={() => sendTest(ch.id)}
                  disabled={!testChatId[ch.id]}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white text-xs"
                >
                  <Send className="h-3 w-3" /> Probar
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

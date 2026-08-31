"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Loader2, Save } from "lucide-react";

interface SystemConfig {
  key: string;
  value: string;
}

export default function AdminSettingsPage() {
  const [configs, setConfigs] = useState<SystemConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetch("/api/admin/settings")
      .then((res) => res.json())
      .then((data) => {
        setConfigs(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const getConfig = (key: string) => configs.find((c) => c.key === key)?.value || "";

  const updateConfig = (key: string, value: string) => {
    setConfigs((prev) => {
      const existing = prev.find((c) => c.key === key);
      if (existing) {
        return prev.map((c) => (c.key === key ? { ...c, value } : c));
      }
      return [...prev, { key, value }];
    });
  };

  const handleSave = async () => {
    setSaving(true);
    setSuccess(false);
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configs }),
      });
      if (res.ok) setSuccess(true);
    } catch {
      // handle error
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-accent" />
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Configuración del Sistema</h1>
        <p className="text-text-secondary mt-1">
          Ajustes globales de la plataforma EATHERIA
        </p>
      </div>

      {success && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          Configuración guardada correctamente
        </div>
      )}

      {/* Platform settings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Plataforma</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Nombre de la Plataforma</Label>
              <Input
                value={getConfig("platform_name") || "EATHERIA"}
                onChange={(e) => updateConfig("platform_name", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>URL de Soporte</Label>
              <Input
                value={getConfig("support_url")}
                onChange={(e) => updateConfig("support_url", e.target.value)}
                placeholder="https://soporte.aetheria.io"
              />
            </div>
            <div className="space-y-2">
              <Label>Email de Soporte</Label>
              <Input
                type="email"
                value={getConfig("support_email")}
                onChange={(e) => updateConfig("support_email", e.target.value)}
                placeholder="soporte@aetheria.io"
              />
            </div>
            <div className="space-y-2">
              <Label>Max Intentos de Login</Label>
              <Input
                type="number"
                value={getConfig("max_login_attempts") || "5"}
                onChange={(e) => updateConfig("max_login_attempts", e.target.value)}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* AI settings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Configuración de IA</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Modelo por Defecto</Label>
              <Input
                value={getConfig("default_ai_model") || "gemini-2.5-flash-lite"}
                onChange={(e) => updateConfig("default_ai_model", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Temperatura por Defecto</Label>
              <Input
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={getConfig("default_temperature") || "0.3"}
                onChange={(e) => updateConfig("default_temperature", e.target.value)}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button variant="cyber" onClick={handleSave} disabled={saving}>
          {saving ? (
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
          ) : (
            <Save className="h-4 w-4 mr-2" />
          )}
          Guardar Configuración
        </Button>
      </div>
    </div>
  );
}

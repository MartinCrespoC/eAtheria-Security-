"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  GitBranch,
  Plus,
  Loader2,
  Trash2,
  CheckCircle2,
  XCircle,
  RefreshCw,
} from "lucide-react";

interface ConnectionData {
  id: string;
  name: string;
  username: string | null;
  isActive: boolean;
  lastSyncAt: Date | null;
  createdAt: Date;
}

export function GitHubConnections({ connections }: { connections: ConnectionData[] }) {
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ name: "", accessToken: "", username: "" });

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/github/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Error al conectar");
        return;
      }

      window.location.reload();
    } catch {
      setError("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("¿Eliminar esta conexión?")) return;
    await fetch(`/api/github/connections/${id}`, { method: "DELETE" });
    window.location.reload();
  };

  const handleSync = async (id: string) => {
    await fetch(`/api/github/connections/${id}/sync`, { method: "POST" });
    window.location.reload();
  };

  return (
    <div className="space-y-6">
      {/* Actions */}
      <div className="flex justify-end">
        <Button variant="cyber" size="sm" onClick={() => setShowForm(!showForm)}>
          <Plus className="h-4 w-4 mr-2" /> Nueva Conexión
        </Button>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-lg font-semibold text-text-primary mb-4">Agregar Conexión GitHub</h3>
          <form onSubmit={handleAdd} className="space-y-4">
            {error && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>Nombre</Label>
                <Input
                  placeholder="Mi Org GitHub"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Owner / Org</Label>
                <Input
                  placeholder="mi-organizacion"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Personal Access Token</Label>
                <Input
                  type="password"
                  placeholder="ghp_..."
                  value={form.accessToken}
                  onChange={(e) => setForm({ ...form, accessToken: e.target.value })}
                  required
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" type="button" onClick={() => setShowForm(false)}>
                Cancelar
              </Button>
              <Button variant="cyber" type="submit" disabled={loading}>
                {loading && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
                Conectar
              </Button>
            </div>
          </form>
        </div>
      )}

      {/* Connections list */}
      {connections.length === 0 && !showForm ? (
        <div className="flex flex-col items-center justify-center h-48 text-text-muted">
          <GitBranch className="h-12 w-12 mb-3 opacity-40" />
          <p className="text-lg font-medium">Sin conexiones</p>
          <p className="text-sm mt-1">Conecta tu cuenta de GitHub para empezar</p>
        </div>
      ) : (
        <div className="space-y-3">
          {connections.map((conn) => (
            <div
              key={conn.id}
              className="rounded-xl border border-border bg-card p-5 flex items-center justify-between"
            >
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 rounded-lg bg-surface flex items-center justify-center">
                  <GitBranch className="h-5 w-5 text-text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-text-primary">{conn.name}</p>
                    <Badge variant={conn.isActive ? "success" : "default"}>
                      {conn.isActive ? (
                        <><CheckCircle2 className="h-3 w-3 mr-1" /> Activa</>
                      ) : (
                        <><XCircle className="h-3 w-3 mr-1" /> Inactiva</>
                      )}
                    </Badge>
                  </div>
                  <p className="text-sm text-text-muted mt-0.5">
                    @{conn.username}
                    {conn.lastSyncAt && (
                      <> · Último sync: {new Date(conn.lastSyncAt).toLocaleDateString("es-ES")}</>
                    )}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleSync(conn.id)}
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-red-400 hover:text-red-300"
                  onClick={() => handleDelete(conn.id)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

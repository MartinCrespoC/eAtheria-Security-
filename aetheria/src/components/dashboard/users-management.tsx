"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Users,
  Plus,
  Search,
  Shield,
  ShieldOff,
  Lock,
  Unlock,
  Clock,
  Loader2,
} from "lucide-react";

interface UserData {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isActive: boolean;
  isBlocked: boolean;
  twoFactorEnabled: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  userRoles: {
    role: { name: string; displayName: string };
  }[];
}

export function UsersManagement({ users }: { users: UserData[] }) {
  const [search, setSearch] = useState("");
  const [showInvite, setShowInvite] = useState(false);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteError, setInviteError] = useState("");
  const [inviteForm, setInviteForm] = useState({
    email: "",
    firstName: "",
    lastName: "",
    role: "analyst",
  });

  const filtered = users.filter((u) => {
    const q = search.toLowerCase();
    return (
      u.email.toLowerCase().includes(q) ||
      u.firstName.toLowerCase().includes(q) ||
      u.lastName.toLowerCase().includes(q)
    );
  });

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteLoading(true);
    setInviteError("");
    try {
      const res = await fetch("/api/users/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(inviteForm),
      });
      if (!res.ok) {
        const data = await res.json();
        setInviteError(data.error || "Error al invitar");
        return;
      }
      window.location.reload();
    } catch {
      setInviteError("Error de conexión");
    } finally {
      setInviteLoading(false);
    }
  };

  const handleToggleBlock = async (userId: string, block: boolean) => {
    await fetch(`/api/users/${userId}/block`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ block }),
    });
    window.location.reload();
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            placeholder="Buscar usuarios..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-10 w-full rounded-lg border border-border bg-card pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
        <Button variant="cyber" size="sm" onClick={() => setShowInvite(!showInvite)}>
          <Plus className="h-4 w-4 mr-2" /> Invitar
        </Button>
      </div>

      {/* Invite form */}
      {showInvite && (
        <div className="rounded-xl border border-border bg-card p-6">
          <h3 className="text-lg font-semibold text-text-primary mb-4">Invitar Usuario</h3>
          <form onSubmit={handleInvite} className="space-y-4">
            {inviteError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {inviteError}
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="space-y-2">
                <Label>Nombre</Label>
                <Input
                  placeholder="Juan"
                  value={inviteForm.firstName}
                  onChange={(e) => setInviteForm({ ...inviteForm, firstName: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Apellido</Label>
                <Input
                  placeholder="García"
                  value={inviteForm.lastName}
                  onChange={(e) => setInviteForm({ ...inviteForm, lastName: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Email</Label>
                <Input
                  type="email"
                  placeholder="juan@empresa.com"
                  value={inviteForm.email}
                  onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Rol</Label>
                <select
                  value={inviteForm.role}
                  onChange={(e) => setInviteForm({ ...inviteForm, role: e.target.value })}
                  className="h-10 w-full rounded-lg border border-border bg-card px-3 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                >
                  <option value="admin">Admin</option>
                  <option value="analyst">Analista</option>
                  <option value="developer">Developer</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" type="button" onClick={() => setShowInvite(false)}>
                Cancelar
              </Button>
              <Button variant="cyber" type="submit" disabled={inviteLoading}>
                {inviteLoading && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
                Invitar
              </Button>
            </div>
          </form>
        </div>
      )}

      {/* Users table */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-text-muted">
          <Users className="h-10 w-10 mb-3 opacity-40" />
          <p>Sin usuarios encontrados</p>
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">Usuario</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">Rol</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">2FA</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">Estado</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-text-muted uppercase">Último acceso</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-text-muted uppercase">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <tr key={u.id} className="border-b border-border hover:bg-surface transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-gradient-to-br from-cyan-500 to-purple-500 flex items-center justify-center text-white font-bold text-xs">
                        {u.firstName[0]}{u.lastName[0]}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-text-primary">{u.firstName} {u.lastName}</p>
                        <p className="text-xs text-text-muted">{u.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {u.userRoles.map((ur, i) => (
                      <Badge key={i} variant="secondary" className="mr-1">
                        {ur.role.displayName}
                      </Badge>
                    ))}
                  </td>
                  <td className="px-4 py-3 text-center">
                    {u.twoFactorEnabled ? (
                      <Shield className="h-4 w-4 text-emerald-500 mx-auto" />
                    ) : (
                      <ShieldOff className="h-4 w-4 text-text-muted mx-auto" />
                    )}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <Badge variant={u.isBlocked ? "destructive" : u.isActive ? "success" : "default"}>
                      {u.isBlocked ? "Bloqueado" : u.isActive ? "Activo" : "Inactivo"}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-right text-xs text-text-muted">
                    {u.lastLoginAt ? (
                      <span className="flex items-center justify-end gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(u.lastLoginAt).toLocaleDateString("es-ES")}
                      </span>
                    ) : (
                      "Nunca"
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleToggleBlock(u.id, !u.isBlocked)}
                      className={u.isBlocked ? "text-emerald-400" : "text-red-400"}
                    >
                      {u.isBlocked ? <Unlock className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

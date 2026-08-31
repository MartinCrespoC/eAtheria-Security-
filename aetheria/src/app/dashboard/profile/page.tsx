"use client";

import { useState } from "react";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Save, Shield, ShieldOff, Key, QrCode, Copy, Check } from "lucide-react";

export default function ProfilePage() {
  const { data: session } = useSession();
  const user = session?.user;
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    firstName: user?.firstName || "",
    lastName: user?.lastName || "",
  });

  const [passwordForm, setPasswordForm] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  // 2FA state
  const [twoFAStep, setTwoFAStep] = useState<"idle" | "qr" | "verify" | "done">("idle");
  const [qrCode, setQrCode] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [twoFALoading, setTwoFALoading] = useState(false);

  const handleSetup2FA = async () => {
    setTwoFALoading(true);
    setError("");
    try {
      const res = await fetch("/api/users/2fa/setup", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Error al configurar 2FA");
        return;
      }
      setQrCode(data.qrCode);
      setTwoFAStep("qr");
    } catch {
      setError("Error de conexión");
    } finally {
      setTwoFALoading(false);
    }
  };

  const handleEnable2FA = async () => {
    if (totpCode.length !== 6) return;
    setTwoFALoading(true);
    setError("");
    try {
      const res = await fetch("/api/users/2fa/enable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Código inválido");
        return;
      }
      setBackupCodes(data.backupCodes);
      setTwoFAStep("done");
      setSuccess("2FA habilitado correctamente");
    } catch {
      setError("Error de conexión");
    } finally {
      setTwoFALoading(false);
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setSuccess("");
    setError("");
    try {
      const res = await fetch("/api/users/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (res.ok) {
        setSuccess("Perfil actualizado");
      } else {
        const data = await res.json();
        setError(data.error || "Error al actualizar");
      }
    } catch {
      setError("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setError("Las contraseñas no coinciden");
      return;
    }
    setLoading(true);
    setSuccess("");
    setError("");
    try {
      const res = await fetch("/api/users/password", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword,
        }),
      });
      if (res.ok) {
        setSuccess("Contraseña actualizada");
        setPasswordForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
      } else {
        const data = await res.json();
        setError(data.error || "Error al cambiar contraseña");
      }
    } catch {
      setError("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  if (!user) return null;

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Mi Perfil</h1>
        <p className="text-text-secondary mt-1">Gestiona tu cuenta y seguridad</p>
      </div>

      {success && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {success}
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Profile info */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Información Personal</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleUpdateProfile} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Nombre</Label>
                <Input
                  value={form.firstName}
                  onChange={(e) => setForm({ ...form, firstName: e.target.value })}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Apellido</Label>
                <Input
                  value={form.lastName}
                  onChange={(e) => setForm({ ...form, lastName: e.target.value })}
                  required
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Email</Label>
              <Input value={user.email} disabled />
            </div>
            <div className="flex justify-end">
              <Button variant="cyber" type="submit" disabled={loading}>
                {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Save className="h-4 w-4 mr-2" />}
                Guardar
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Password change */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Key className="h-4 w-4" /> Cambiar Contraseña
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div className="space-y-2">
              <Label>Contraseña actual</Label>
              <Input
                type="password"
                value={passwordForm.currentPassword}
                onChange={(e) =>
                  setPasswordForm({ ...passwordForm, currentPassword: e.target.value })
                }
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Nueva contraseña</Label>
                <Input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) =>
                    setPasswordForm({ ...passwordForm, newPassword: e.target.value })
                  }
                  required
                  minLength={8}
                />
              </div>
              <div className="space-y-2">
                <Label>Confirmar contraseña</Label>
                <Input
                  type="password"
                  value={passwordForm.confirmPassword}
                  onChange={(e) =>
                    setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })
                  }
                  required
                />
              </div>
            </div>
            <div className="flex justify-end">
              <Button variant="outline" type="submit" disabled={loading}>
                Cambiar Contraseña
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* 2FA */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Autenticación de Dos Factores</CardTitle>
          <CardDescription>
            Protege tu cuenta con un código temporal adicional
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Status display */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {user.twoFactorEnabled || twoFAStep === "done" ? (
                <>
                  <Shield className="h-5 w-5 text-emerald-500" />
                  <div>
                    <p className="text-sm font-medium text-text-primary">2FA Habilitado</p>
                    <p className="text-xs text-text-muted">Tu cuenta está protegida</p>
                  </div>
                </>
              ) : (
                <>
                  <ShieldOff className="h-5 w-5 text-amber-500" />
                  <div>
                    <p className="text-sm font-medium text-text-primary">2FA Deshabilitado</p>
                    <p className="text-xs text-text-muted">Activa 2FA para mayor seguridad</p>
                  </div>
                </>
              )}
            </div>
            <Badge variant={user.twoFactorEnabled || twoFAStep === "done" ? "success" : "warning"}>
              {user.twoFactorEnabled || twoFAStep === "done" ? "Activo" : "Inactivo"}
            </Badge>
          </div>

          {/* Setup button */}
          {!user.twoFactorEnabled && twoFAStep === "idle" && (
            <Button variant="cyber" onClick={handleSetup2FA} disabled={twoFALoading}>
              {twoFALoading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <QrCode className="h-4 w-4 mr-2" />
              )}
              Configurar 2FA
            </Button>
          )}

          {/* QR Code step */}
          {twoFAStep === "qr" && qrCode && (
            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-surface p-4">
                <p className="text-sm text-text-primary mb-3">
                  Escanea este código QR con tu app de autenticación (Google Authenticator, Authy, etc.)
                </p>
                <div className="flex justify-center">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={qrCode} alt="QR Code 2FA" className="rounded-lg" width={200} height={200} />
                </div>
              </div>
              <Button variant="cyber" onClick={() => setTwoFAStep("verify")}>
                Siguiente — Verificar Código
              </Button>
            </div>
          )}

          {/* Verify step */}
          {twoFAStep === "verify" && (
            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-surface p-4">
                <p className="text-sm text-text-primary mb-3">
                  Ingresa el código de 6 dígitos de tu app de autenticación
                </p>
                <div className="flex items-center gap-3">
                  <Input
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="000000"
                    className="text-center text-2xl tracking-widest font-mono max-w-[200px]"
                    maxLength={6}
                  />
                  <Button
                    variant="cyber"
                    onClick={handleEnable2FA}
                    disabled={totpCode.length !== 6 || twoFALoading}
                  >
                    {twoFALoading ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <Shield className="h-4 w-4 mr-2" />
                    )}
                    Activar
                  </Button>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setTwoFAStep("qr")}>
                Volver al QR
              </Button>
            </div>
          )}

          {/* Backup codes step */}
          {twoFAStep === "done" && backupCodes.length > 0 && (
            <div className="space-y-3">
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                <p className="text-sm font-medium text-amber-400 mb-2">
                  Guarda estos códigos de respaldo en un lugar seguro
                </p>
                <p className="text-xs text-text-secondary mb-3">
                  Cada código solo se puede usar una vez si pierdes acceso a tu app de autenticación.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {backupCodes.map((code, i) => (
                    <div key={i} className="rounded bg-card px-3 py-1.5 text-center font-mono text-sm text-text-primary">
                      {code}
                    </div>
                  ))}
                </div>
              </div>
              <Button variant="outline" size="sm" onClick={copyBackupCodes}>
                {copied ? (
                  <Check className="h-3 w-3 mr-1 text-emerald-400" />
                ) : (
                  <Copy className="h-3 w-3 mr-1" />
                )}
                {copied ? "Copiados" : "Copiar Códigos"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

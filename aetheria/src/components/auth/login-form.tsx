"use client";

import { useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { signIn } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { srpClientStep1, srpClientStep2, srpClientStep3 } from "@/lib/srp-client";
import { useLanguage } from "@/components/providers/language-provider";
import Link from "next/link";
import {
  AlertCircle,
  Eye,
  EyeOff,
  Mail,
  Lock,
  Shield,
  Loader2,
} from "lucide-react";

export function LoginForm() {
  const { t } = useLanguage();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") || "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [show2FA, setShow2FA] = useState(false);
  // SRP state kept alive between the password proof and the TOTP retry
  const srpRef = useRef<{
    clientPublicEphemeral: string;
    clientProof: string;
    clientSession: ReturnType<typeof srpClientStep2>;
    clientEphemeralPublic: string;
  } | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (show2FA) {
      await handleTotpSubmit();
      return;
    }
    setLoading(true);
    setError(null);

    try {
      // SRP Step 1: Client generates ephemeral and sends to server
      const clientEphemeral = srpClientStep1();

      const step1Res = await fetch("/api/auth/srp/step1", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          clientPublicEphemeral: clientEphemeral.public,
        }),
      });

      if (!step1Res.ok) {
        // Legacy account without SRP credentials — fall back to classic
        // bcrypt auth through NextAuth (password travels over TLS only).
        if (step1Res.status === 401) {
          const legacy = await signIn("credentials", {
            email,
            password,
            redirect: false,
          });
          if (legacy?.ok) {
            window.location.href = callbackUrl;
            return;
          }
        }
        const error = await step1Res.json().catch(() => ({}));
        setError(error.error || t("auth.login.errorGeneric"));
        return;
      }

      const { salt, serverPublicEphemeral } = await step1Res.json();

      // SRP Step 2: Client derives session and generates proof
      const clientSession = srpClientStep2(
        clientEphemeral.secret,
        serverPublicEphemeral,
        salt,
        email,
        password
      );

      // Send proof to server
      const step2Res = await fetch("/api/auth/srp/step2", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          clientPublicEphemeral: clientEphemeral.public,
          clientProof: clientSession.proof,
        }),
      });

      if (!step2Res.ok) {
        const error = await step2Res.json();
        setError(error.error || t("auth.login.errorInvalid"));
        return;
      }

      const step2Data = await step2Res.json();

      // 2FA enabled: keep the SRP state alive and ask for the TOTP code.
      // The proof is re-sent together with the code (server keeps the
      // ephemeral alive until full success).
      if (step2Data.requiresTwoFactor) {
        srpRef.current = {
          clientPublicEphemeral: clientEphemeral.public,
          clientProof: clientSession.proof,
          clientSession,
          clientEphemeralPublic: clientEphemeral.public,
        };
        setShow2FA(true);
        return;
      }

      await finishLogin(step2Data, clientEphemeral.public, clientSession);
    } catch (err) {
      console.error("[SRP LOGIN ERROR]", err);
      setError(t("auth.login.errorRetry"));
    } finally {
      setLoading(false);
    }
  }

  async function handleTotpSubmit() {
    if (!srpRef.current) {
      setShow2FA(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { clientPublicEphemeral, clientProof, clientSession, clientEphemeralPublic } = srpRef.current;
      const step2Res = await fetch("/api/auth/srp/step2", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          clientPublicEphemeral,
          clientProof,
          totpCode,
        }),
      });

      if (!step2Res.ok) {
        const error = await step2Res.json().catch(() => ({}));
        setError(error.error || t("auth.login.errorInvalid"));
        return;
      }

      const step2Data = await step2Res.json();
      srpRef.current = null;
      await finishLogin(step2Data, clientEphemeralPublic, clientSession);
    } catch (err) {
      console.error("[2FA LOGIN ERROR]", err);
      setError(t("auth.login.errorRetry"));
    } finally {
      setLoading(false);
    }
  }

  async function finishLogin(
    step2Data: { serverProof: string; authToken: string },
    clientEphemeralPublic: string,
    clientSession: ReturnType<typeof srpClientStep2>
  ) {
    const { serverProof, authToken } = step2Data;

    // SRP Step 3: Verify server proof (prevents MITM)
    try {
      srpClientStep3(clientEphemeralPublic, clientSession, serverProof);
    } catch {
      setError(t("auth.login.errorServerVerify"));
      return;
    }

    // Use authToken to authenticate with NextAuth
    const result = await signIn("credentials", {
      email,
      srpProof: authToken,
      redirect: false,
    });

    if (result?.error) {
      setError(t("auth.login.errorSession"));
      return;
    }

    // Login successful - redirect
    window.location.href = callbackUrl;
  }

  return (
    <>
      <div className="text-center mb-8">
        <h1 className="text-3xl font-black text-white mb-2">
          {t("auth.login.title")}
        </h1>
        <p className="text-slate-400 text-sm">{t("auth.login.subtitle")}</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm animate-slide-up">
          <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!show2FA ? (
        <>
          <div className="space-y-2">
            <Label htmlFor="email">{t("auth.login.emailLabel")}</Label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <Input
                id="email"
                type="text"
                placeholder={t("auth.login.emailPlaceholder")}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
                className="pl-10"
                autoComplete="username"
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">{t("auth.login.passwordLabel")}</Label>
              <button
                type="button"
                className="text-xs text-cyan-400 hover:text-cyan-300"
              >
                {t("auth.login.forgot")}
              </button>
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
                className="pl-10 pr-10"
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
          </div>
        </>
      ) : (
        <div className="space-y-4 animate-slide-up">
          <div className="flex items-center gap-3 p-4 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
            <Shield className="h-5 w-5 text-cyan-400 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-white">
                {t("auth.login.2faTitle")}
              </p>
              <p className="text-xs text-slate-400">
                {t("auth.login.2faSubtitle")}
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="totp">{t("auth.login.2faCode")}</Label>
            <Input
              id="totp"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              placeholder="000000"
              maxLength={6}
              value={totpCode}
              onChange={(e) =>
                setTotpCode(e.target.value.replace(/\D/g, ""))
              }
              required
              disabled={loading}
              className="text-center text-2xl font-mono tracking-[0.5em] h-14"
              autoComplete="one-time-code"
              autoFocus
            />
          </div>

          <button
            type="button"
            onClick={() => {
              setShow2FA(false);
              setTotpCode("");
              srpRef.current = null;
            }}
            className="text-xs text-slate-400 hover:text-cyan-400"
          >
            {t("auth.login.backToLogin")}
          </button>
        </div>
      )}

      <Button
        type="submit"
        variant="cyber"
        className="w-full h-12"
        disabled={loading}
      >
        {loading
          ? t("auth.login.verifying")
          : show2FA
            ? t("auth.login.verifyCode")
            : t("auth.login.submit")}
      </Button>

      <div className="mt-6 text-center">
        <p className="text-sm text-slate-500">
          Modo individual — acceso con credenciales configuradas en el setup
        </p>
      </div>
      </form>

      <p className="text-center text-xs text-slate-500 mt-6">
        {t("auth.login.termsA")}{" "}
        <Link href="/terms" className="underline hover:text-slate-400">
          {t("auth.login.termsLink")}
        </Link>{" "}
        {t("auth.login.termsAnd")}{" "}
        <Link href="/privacy" className="underline hover:text-slate-400">
          {t("auth.login.privacyLink")}
        </Link>
      </p>
    </>
  );
}

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ShieldCheck,
  Loader2,
  ArrowRight,
  ArrowLeft,
  Eye,
  EyeOff,
  AlertCircle,
} from "lucide-react";

export default function AdminSetupPage() {
  const router = useRouter();

  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const passwordsMatch = password === confirmPassword;
  const passwordLongEnough = password.length >= 8;
  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const formValid =
    firstName.trim() &&
    emailValid &&
    passwordLongEnough &&
    passwordsMatch;

  async function handleCreateAdmin() {
    if (!formValid) return;

    setCreating(true);
    setError(null);

    try {
      const res = await fetch("/api/setup/create-admin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName: firstName.trim(),
          lastName: lastName.trim(),
          email: email.toLowerCase().trim(),
          password,
        }),
      });

      const data = await res.json();

      if (data.success) {
        router.push("/setup/ai");
      } else {
        setError(data.error || "Failed to create admin account");
      }
    } catch {
      setError("Failed to reach the server. Please try again.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div>
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-purple-500/10 border border-purple-500/30 mb-3">
          <ShieldCheck className="w-7 h-7 text-purple-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-1">
          Create System Admin
        </h2>
        <p className="text-sm text-slate-400">
          This account will have full administrative access to the platform
        </p>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="firstName">First Name</Label>
            <Input
              id="firstName"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              placeholder="John"
              disabled={creating}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="lastName">Last Name</Label>
            <Input
              id="lastName"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              placeholder="Doe"
              disabled={creating}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="email">Email Address</Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="admin@example.com"
            disabled={creating}
          />
          {email && !emailValid && (
            <p className="text-xs text-red-400">Please enter a valid email address</p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              disabled={creating}
              className="pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
            >
              {showPassword ? (
                <EyeOff className="w-4 h-4" />
              ) : (
                <Eye className="w-4 h-4" />
              )}
            </button>
          </div>
          {password && !passwordLongEnough && (
            <p className="text-xs text-red-400">
              Password must be at least 8 characters
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm Password</Label>
          <Input
            id="confirmPassword"
            type={showPassword ? "text" : "password"}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter password"
            disabled={creating}
          />
          {confirmPassword && !passwordsMatch && (
            <p className="text-xs text-red-400">Passwords do not match</p>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Security note */}
      <div className="mt-4 p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5">
        <p className="text-xs text-slate-400">
          <span className="text-cyan-400 font-semibold">Security:</span> Your
          password will be hashed with bcrypt (12 rounds) before storage. We
          never store plaintext passwords.
        </p>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between mt-6">
        <Button
          variant="ghost"
          onClick={() => router.push("/setup/database")}
          disabled={creating}
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </Button>

        <Button
          onClick={handleCreateAdmin}
          disabled={!formValid || creating}
        >
          {creating ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Creating...
            </>
          ) : (
            <>
              Create Admin
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

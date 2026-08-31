import { Suspense } from "react";
import { LoginForm } from "@/components/auth/login-form";
import { ParticlesBackground } from "@/components/effects/particles";
import { MatrixRain } from "@/components/effects/matrix-rain";
import { Logo } from "@/components/brand/logo";
import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sign In - EATHERIA Security",
};

export default function LoginPage() {
  return (
    <div className="relative min-h-screen flex items-center justify-center overflow-hidden matrix-bg">
      <MatrixRain opacity={0.08} />
      <ParticlesBackground count={40} />

      {/* Animated orbs */}
      <div className="absolute top-0 left-0 w-96 h-96 bg-cyan-500/30 rounded-full blur-3xl animate-float" />
      <div
        className="absolute bottom-0 right-0 w-96 h-96 bg-purple-500/30 rounded-full blur-3xl animate-float"
        style={{ animationDelay: "2s" }}
      />

      {/* Scanning line */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan-500 to-transparent animate-scan-line" />
      </div>

      <div className="relative z-10 w-full max-w-md px-6">
        <Link href="/" className="flex justify-center mb-8">
          <Logo size="lg" />
        </Link>

        <div className="glass-strong rounded-2xl p-8 border border-cyan-500/20 shadow-2xl shadow-cyan-500/10 animate-slide-up">
          <Suspense fallback={<div className="h-48" />}>
            <LoginForm />
          </Suspense>
        </div>
      </div>
    </div>
  );
}

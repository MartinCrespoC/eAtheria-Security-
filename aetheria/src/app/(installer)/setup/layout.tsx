"use client";

import { usePathname } from "next/navigation";
import { Logo } from "@/components/brand/logo";
import { ParticlesBackground } from "@/components/effects/particles";
import {
  Database,
  ShieldCheck,
  Sparkles,
  MessageSquare,
  CheckCircle2,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Step {
  label: string;
  icon: LucideIcon;
  path: string;
}

const STEPS: Step[] = [
  { label: "Database", icon: Database, path: "/setup/database" },
  { label: "Admin", icon: ShieldCheck, path: "/setup/admin" },
  { label: "IA", icon: Sparkles, path: "/setup/ai" },
  { label: "WhatsApp", icon: MessageSquare, path: "/setup/whatsapp" },
  { label: "Complete", icon: CheckCircle2, path: "/setup/complete" },
];

function getStepIndex(pathname: string): number {
  for (let i = 0; i < STEPS.length; i++) {
    if (pathname.startsWith(STEPS[i].path)) return i;
  }
  return -1; // Welcome page
}

function SetupStepper() {
  const pathname = usePathname();
  const currentIndex = getStepIndex(pathname);

  if (currentIndex === -1) return null;

  return (
    <div className="flex items-center justify-center gap-2 sm:gap-4 mb-8">
      {STEPS.map((step, index) => {
        const Icon = step.icon;
        const isCompleted = index < currentIndex;
        const isActive = index === currentIndex;
        const isPending = index > currentIndex;

        return (
          <div key={step.path} className="flex items-center">
            {/* Step circle */}
            <div className="flex flex-col items-center gap-2">
              <div
                className={cn(
                  "flex items-center justify-center w-10 h-10 sm:w-12 sm:h-12 rounded-full border-2 transition-all duration-300",
                  isCompleted &&
                    "border-green-500/50 bg-green-500/10 text-green-400",
                  isActive &&
                    "border-cyan-500 bg-cyan-500/10 text-cyan-400 glow-cyan animate-pulse-glow",
                  isPending &&
                    "border-slate-700 bg-slate-900/50 text-slate-600"
                )}
              >
                <Icon className="w-5 h-5 sm:w-6 sm:h-6" />
              </div>
              <span
                className={cn(
                  "text-xs font-medium transition-colors",
                  isCompleted && "text-green-400",
                  isActive && "text-cyan-400",
                  isPending && "text-slate-600"
                )}
              >
                {step.label}
              </span>
            </div>

            {/* Connector line */}
            {index < STEPS.length - 1 && (
              <div
                className={cn(
                  "w-8 sm:w-16 h-0.5 mx-1 sm:mx-2 mb-6 transition-all duration-300",
                  isCompleted ? "bg-green-500/50" : "bg-slate-700"
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function SetupLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden matrix-bg py-12 px-4">
      <ParticlesBackground count={40} />

      {/* Animated orbs */}
      <div className="absolute top-0 left-0 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-float" />
      <div
        className="absolute bottom-0 right-0 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-float"
        style={{ animationDelay: "2s" }}
      />

      {/* Scanning line */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent animate-scan-line" />
      </div>

      <div className="relative z-10 w-full max-w-2xl">
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <Logo size="lg" />
        </div>

        {/* Stepper */}
        <SetupStepper />

        {/* Content card */}
        <div className="glass-strong rounded-2xl p-8 border border-cyan-500/20 shadow-2xl shadow-cyan-500/10 animate-slide-up">
          {children}
        </div>

        <p className="text-center text-xs text-slate-500 mt-6">
          EATHERIA Security Platform — Initial Setup Wizard
        </p>
      </div>
    </div>
  );
}

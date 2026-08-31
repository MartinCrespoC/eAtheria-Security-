"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Database,
  ShieldCheck,
  Building2,
  Sparkles,
  MessageSquare,
  Rocket,
  Loader2,
  ArrowRight,
} from "lucide-react";

export default function SetupWelcomePage() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);
  const [configured, setConfigured] = useState(false);
  const [currentStep, setCurrentStep] = useState<string | null>(null);

  useEffect(() => {
    async function checkStatus() {
      try {
        const res = await fetch("/api/setup/status");
        if (res.ok) {
          const data = await res.json();
          if (data.configured) {
            setConfigured(true);
          } else if (data.step) {
            setCurrentStep(data.step);
          }
        }
      } catch {
        // DB might not be initialized yet — that's fine, show setup
      } finally {
        setChecking(false);
      }
    }
    checkStatus();
  }, []);

  useEffect(() => {
    if (configured) {
      router.push("/dashboard");
    }
  }, [configured, router]);

  // If setup is already partway through (e.g. the database was provisioned
  // automatically by Docker), jump straight to the pending step instead of
  // making the user walk through the steps that are already done.
  useEffect(() => {
    if (!checking && !configured && currentStep && currentStep !== "database") {
      router.push(`/setup/${currentStep}`);
    }
  }, [checking, configured, currentStep, router]);

  if (checking) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
      </div>
    );
  }

  const steps = [
    {
      icon: Database,
      title: "Configure Database",
      description: "Set up your database connection (PostgreSQL, SQLite, or MySQL)",
    },
    {
      icon: ShieldCheck,
      title: "Create Admin Account",
      description: "Set up the first system administrator with full access",
    },
    {
      icon: Building2,
      title: "Create First Company",
      description: "Establish your organization and link it to the admin",
    },
    {
      icon: Sparkles,
      title: "Connect AI Provider",
      description: "Add an API key so security analyses run from the very first scan",
    },
    {
      icon: MessageSquare,
      title: "Connect WhatsApp (optional)",
      description: "Link a WhatsApp number via QR code for scan alerts and report notifications",
    },
    {
      icon: Rocket,
      title: "Launch EATHERIA",
      description: "Finalize configuration and start using the platform",
    },
  ];

  return (
    <div className="text-center">
      <h1 className="text-3xl font-black text-white mb-3">
        Welcome to <span className="gradient-text">EATHERIA</span>
      </h1>
      <p className="text-slate-400 text-sm mb-8 max-w-md mx-auto">
        Let&apos;s get your security platform up and running. This setup wizard
        will guide you through the initial configuration in just a few steps.
      </p>

      <div className="space-y-3 text-left mb-8">
        {steps.map((step, index) => {
          const Icon = step.icon;
          return (
            <div
              key={index}
              className="flex items-start gap-4 p-4 rounded-lg border border-slate-800/60 bg-slate-900/40 hover:border-cyan-500/30 transition-colors"
            >
              <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                <Icon className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-cyan-400">
                    Step {index + 1}
                  </span>
                  <h3 className="text-sm font-semibold text-white">
                    {step.title}
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  {step.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <Button
        size="lg"
        className="w-full"
        onClick={() => router.push("/setup/database")}
      >
        Start Setup
        <ArrowRight className="w-5 h-5" />
      </Button>

      <p className="text-xs text-slate-500 mt-4">
        This wizard is only accessible during initial setup. Once completed, it
        will be locked.
      </p>
    </div>
  );
}

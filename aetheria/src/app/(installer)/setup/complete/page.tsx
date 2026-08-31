"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  CheckCircle2,
  Loader2,
  Rocket,
  Database,
  ShieldCheck,
  Building2,
  Sparkles,
  ArrowRight,
} from "lucide-react";

interface SetupSummary {
  provider?: string;
  adminEmail?: string;
  companyName?: string;
  plan?: string;
  aiProvider?: string;
}

export default function SetupCompletePage() {
  const router = useRouter();

  const [summary, setSummary] = useState<SetupSummary>({});
  const [loading, setLoading] = useState(true);
  const [completing, setCompleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchSummary() {
      try {
        const res = await fetch("/api/setup/status");
        if (res.ok) {
          const data = await res.json();
          setSummary({
            provider: data.provider,
            adminEmail: data.adminEmail,
            companyName: data.companyName,
            plan: data.plan,
            aiProvider: data.aiProvider,
          });
        }
      } catch {
        // Non-critical — we can still complete setup
      } finally {
        setLoading(false);
      }
    }
    fetchSummary();
  }, []);

  async function handleComplete() {
    setCompleting(true);
    setError(null);

    try {
      const res = await fetch("/api/setup/complete", {
        method: "POST",
      });

      const data = await res.json();

      if (data.success) {
        router.push("/login");
      } else {
        setError(data.error || "Failed to complete setup");
      }
    } catch {
      setError("Failed to reach the server. Please try again.");
    } finally {
      setCompleting(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
      </div>
    );
  }

  const summaryItems = [
    {
      icon: Database,
      label: "Database",
      value: summary.provider
        ? summary.provider.charAt(0).toUpperCase() +
          summary.provider.slice(1)
        : "Configured",
    },
    {
      icon: ShieldCheck,
      label: "Admin Account",
      value: summary.adminEmail || "Created",
    },
    {
      icon: Building2,
      label: "Company",
      value: summary.companyName
        ? `${summary.companyName} (${summary.plan || "enterprise"})`
        : "Created",
    },
    {
      icon: Sparkles,
      label: "AI Provider",
      value: summary.aiProvider || "Not configured — analyses disabled",
    },
  ];

  return (
    <div className="text-center">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-green-500/10 border border-green-500/30 mb-4 animate-pulse-glow">
        <Rocket className="w-8 h-8 text-green-400" />
      </div>

      <h2 className="text-2xl font-bold text-white mb-2">
        Ready to Launch!
      </h2>
      <p className="text-sm text-slate-400 mb-8">
        Review your configuration and complete the setup to start using
        EATHERIA.
      </p>

      {/* Summary */}
      <div className="space-y-3 text-left mb-8">
        {summaryItems.map((item, index) => {
          const Icon = item.icon;
          return (
            <div
              key={index}
              className="flex items-center gap-4 p-4 rounded-lg border border-slate-800/60 bg-slate-900/40"
            >
              <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-green-500/10 border border-green-500/30 flex items-center justify-center">
                <Icon className="w-5 h-5 text-green-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs text-slate-500">{item.label}</div>
                <div className="text-sm font-medium text-white truncate">
                  {item.value}
                </div>
              </div>
              <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0" />
            </div>
          );
        })}
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      <Button
        size="lg"
        className="w-full"
        onClick={handleComplete}
        disabled={completing}
      >
        {completing ? (
          <>
            <Loader2 className="w-5 h-5 animate-spin" />
            Finalizing...
          </>
        ) : (
          <>
            <Rocket className="w-5 h-5" />
            Finish Setup
            <ArrowRight className="w-5 h-5" />
          </>
        )}
      </Button>

      <p className="text-xs text-slate-500 mt-4">
        After completing, you will be redirected to the login page. The setup
        wizard will be permanently locked.
      </p>
    </div>
  );
}

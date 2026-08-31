"use client";

import { useEffect, useRef } from "react";
import { AppWindow, Scan, Bug, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";

interface StatsProps {
  stats: {
    applications: number;
    analyses: number;
    vulnerabilities: number;
    criticalVulns: number;
  };
}

function useStatCards() {
  const { t } = useLanguage();
  return [
    {
      key: "applications" as const,
      label: t("dashboard.home.apps"),
      subtitle: t("dashboard.home.appsActive"),
      icon: AppWindow,
      color: "cyan",
      trend: null as number | null,
    },
    {
      key: "analyses" as const,
      label: t("dashboard.home.analyses"),
      subtitle: t("dashboard.home.analysesDone"),
      icon: Scan,
      color: "purple",
      trend: null as number | null,
    },
    {
      key: "vulnerabilities" as const,
      label: t("dashboard.home.vulns"),
      subtitle: t("dashboard.home.vulnsDetected"),
      icon: Bug,
      color: "amber",
      trend: null as number | null,
    },
    {
      key: "criticalVulns" as const,
      label: t("dashboard.home.critical"),
      subtitle: t("dashboard.home.criticalOpen"),
      icon: AlertTriangle,
      color: "red",
      trend: null as number | null,
    },
  ];
}

const COLOR_MAP: Record<string, { dark: { bg: string; border: string; icon: string; glow: string }; light: { bg: string; border: string; icon: string; glow: string } }> = {
  cyan: {
    dark: { bg: "bg-cyan-500/[0.08]", border: "border-cyan-500/20", icon: "from-cyan-500 to-blue-500", glow: "shadow-cyan-500/10" },
    light: { bg: "bg-cyan-50", border: "border-cyan-200/60", icon: "from-cyan-500 to-blue-500", glow: "shadow-cyan-200/40" },
  },
  purple: {
    dark: { bg: "bg-purple-500/[0.08]", border: "border-purple-500/20", icon: "from-purple-500 to-pink-500", glow: "shadow-purple-500/10" },
    light: { bg: "bg-purple-50", border: "border-purple-200/60", icon: "from-purple-500 to-pink-500", glow: "shadow-purple-200/40" },
  },
  amber: {
    dark: { bg: "bg-amber-500/[0.08]", border: "border-amber-500/20", icon: "from-amber-500 to-orange-500", glow: "shadow-amber-500/10" },
    light: { bg: "bg-amber-50", border: "border-amber-200/60", icon: "from-amber-500 to-orange-500", glow: "shadow-amber-200/40" },
  },
  red: {
    dark: { bg: "bg-red-500/[0.08]", border: "border-red-500/20", icon: "from-red-500 to-rose-500", glow: "shadow-red-500/10" },
    light: { bg: "bg-red-50", border: "border-red-200/60", icon: "from-red-500 to-rose-500", glow: "shadow-red-200/40" },
  },
};

function AnimatedCounter({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (value === 0) { el.textContent = "0"; return; }
    const duration = 800;
    const start = performance.now();
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(value * eased).toLocaleString();
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value]);

  return <span ref={ref}>0</span>;
}

export function DashboardStats({ stats }: StatsProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const STAT_CARDS = useStatCards();

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {STAT_CARDS.map((card, i) => {
        const colors = COLOR_MAP[card.color][isDark ? "dark" : "light"];
        return (
          <div
            key={card.key}
            className={cn(
              "group relative rounded-xl border p-5 transition-all duration-300 hover:scale-[1.02] hover:shadow-lg cursor-default",
              colors.border, colors.bg, colors.glow,
              "animate-slide-up"
            )}
            style={{ animationDelay: `${i * 80}ms` }}
          >
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <p className={cn("text-xs font-semibold uppercase tracking-wider", isDark ? "text-text-secondary" : "text-text-muted")}>
                  {card.label}
                </p>
                <p className={cn("text-3xl font-bold tabular-nums", isDark ? "text-text-primary" : "text-text-primary")}>
                  <AnimatedCounter value={stats[card.key]} />
                </p>
                <p className={cn("text-xs", isDark ? "text-text-muted" : "text-text-secondary")}>
                  {card.subtitle}
                </p>
              </div>
              <div className={cn("h-11 w-11 rounded-xl bg-gradient-to-br flex items-center justify-center shadow-lg transition-transform duration-300 group-hover:scale-110", colors.icon)}>
                <card.icon className="h-5 w-5 text-text-primary" />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

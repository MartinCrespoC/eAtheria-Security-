"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";
import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";

interface SecurityScoreRingProps {
  score: number | null;
}

function getScoreConfig(score: number | null, t: (p: string) => string) {
  if (score === null)
    return { label: t("dashboard.home.noData"), color: "text-text-secondary", ring: "#64748b", icon: ShieldQuestion };
  if (score >= 80)
    return { label: t("dashboard.home.excellent"), color: "text-emerald-400", ring: "#10b981", icon: ShieldCheck };
  if (score >= 60)
    return { label: t("dashboard.home.good"), color: "text-accent", ring: "#06b6d4", icon: ShieldCheck };
  if (score >= 40)
    return { label: t("dashboard.home.moderate"), color: "text-amber-400", ring: "#f59e0b", icon: ShieldAlert };
  return { label: t("dashboard.home.criticalState"), color: "text-red-400", ring: "#ef4444", icon: ShieldAlert };
}

export function SecurityScoreRing({ score }: SecurityScoreRingProps) {
  const { theme } = useTheme();
  const { t } = useLanguage();
  const isDark = theme === "dark";
  const config = getScoreConfig(score, t);
  const circleRef = useRef<SVGCircleElement>(null);

  const radius = 58;
  const circumference = 2 * Math.PI * radius;
  const progress = score !== null ? ((100 - score) / 100) * circumference : circumference;

  useEffect(() => {
    const el = circleRef.current;
    if (!el) return;
    el.style.transition = "none";
    el.style.strokeDashoffset = `${circumference}`;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.style.transition = "stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)";
        el.style.strokeDashoffset = `${progress}`;
      });
    });
  }, [score, circumference, progress]);

  return (
    <div
      className={cn(
        "rounded-xl border p-6 flex flex-col items-center transition-colors duration-300 h-full",
        isDark
          ? "border-border bg-white/[0.02]"
          : "border-border bg-white shadow-sm"
      )}
    >
      <h3
        className={cn(
          "text-lg font-semibold mb-4 self-start",
          isDark ? "text-text-primary" : "text-text-primary"
        )}
      >
        {t("dashboard.home.score")}
      </h3>

      <div className="relative flex items-center justify-center my-2">
        <svg width="140" height="140" className="-rotate-90">
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={isDark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)"}
            strokeWidth="10"
          />
          <circle
            ref={circleRef}
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={config.ring}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={cn(
              "text-3xl font-bold tabular-nums",
              isDark ? "text-text-primary" : "text-text-primary"
            )}
          >
            {score !== null ? score : "—"}
          </span>
          <span
            className={cn(
              "text-xs",
              isDark ? "text-text-muted" : "text-text-secondary"
            )}
          >
            / 100
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 mt-2">
        <config.icon className={cn("h-4 w-4", config.color)} />
        <span className={cn("text-sm font-medium", config.color)}>
          {config.label}
        </span>
      </div>

      <p
        className={cn(
          "text-xs text-center mt-3",
          isDark ? "text-text-muted" : "text-text-secondary"
        )}
      >
        {score === null
          ? t("dashboard.home.firstAnalysis")
          : t("dashboard.home.scoreBased")}
      </p>
    </div>
  );
}

"use client";

import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";
import { Shield } from "lucide-react";

export function WelcomeBanner({ firstName }: { firstName: string }) {
  const { theme } = useTheme();
  const { t } = useLanguage();
  const isDark = theme === "dark";

  const hour = new Date().getHours();
  const greeting =
    hour < 12
      ? t("dashboard.home.goodMorning")
      : hour < 19
        ? t("dashboard.home.goodAfternoon")
        : t("dashboard.home.goodEvening");

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border p-6 transition-colors duration-300",
        isDark
          ? "border-border bg-gradient-to-r from-cyan-500/[0.08] via-transparent to-purple-500/[0.08]"
          : "border-border bg-gradient-to-r from-cyan-50/80 via-white to-purple-50/80 shadow-sm"
      )}
    >
      {/* Subtle grid overlay */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(6,182,212,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.4) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />

      <div className="relative flex items-center justify-between">
        <div>
          <h1
            className={cn(
              "text-2xl font-bold",
              isDark ? "text-text-primary" : "text-text-primary"
            )}
          >
            {greeting},{" "}
            <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
              {firstName}
            </span>
          </h1>
          <p
            className={cn(
              "mt-1 text-sm",
              isDark ? "text-text-secondary" : "text-text-muted"
            )}
          >
            {t("dashboard.home.subtitle")}
          </p>
        </div>
        <div
          className={cn(
            "hidden sm:flex h-12 w-12 rounded-xl items-center justify-center",
            isDark ? "bg-white/[0.05]" : "bg-cyan-50"
          )}
        >
          <Shield
            className={cn(
              "h-6 w-6",
              isDark ? "text-accent" : "text-cyan-600"
            )}
          />
        </div>
      </div>
    </div>
  );
}

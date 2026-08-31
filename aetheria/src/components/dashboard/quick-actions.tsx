"use client";

import Link from "next/link";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";
import {
  Plus,
  Scan,
  GitBranch,
  FileKey2,
  ArrowRight,
} from "lucide-react";

function useActions() {
  const { t } = useLanguage();
  return [
    {
      title: t("dashboard.home.newApp"),
      description: t("dashboard.home.newAppDesc"),
      href: "/dashboard/applications/new",
      icon: Plus,
      color: "cyan",
    },
    {
      title: t("dashboard.home.runAnalysis"),
      description: t("dashboard.home.runAnalysisDesc"),
      href: "/dashboard/analyses",
      icon: Scan,
      color: "purple",
    },
    {
      title: t("dashboard.home.connectGithub"),
      description: t("dashboard.home.connectGithubDesc"),
      href: "/dashboard/github",
      icon: GitBranch,
      color: "emerald",
    },
    {
      title: t("dashboard.home.apiKeys"),
      description: t("dashboard.home.apiKeysDesc"),
      href: "/dashboard/profile",
      icon: FileKey2,
      color: "amber",
    },
  ];
}

const COLOR_CLASSES: Record<
  string,
  { dark: { bg: string; icon: string }; light: { bg: string; icon: string } }
> = {
  cyan: {
    dark: { bg: "bg-cyan-500/10 group-hover:bg-cyan-500/20", icon: "text-accent" },
    light: { bg: "bg-cyan-50 group-hover:bg-cyan-100", icon: "text-cyan-600" },
  },
  purple: {
    dark: { bg: "bg-purple-500/10 group-hover:bg-purple-500/20", icon: "text-purple-400" },
    light: { bg: "bg-purple-50 group-hover:bg-purple-100", icon: "text-purple-600" },
  },
  emerald: {
    dark: { bg: "bg-emerald-500/10 group-hover:bg-emerald-500/20", icon: "text-emerald-400" },
    light: { bg: "bg-emerald-50 group-hover:bg-emerald-100", icon: "text-emerald-600" },
  },
  amber: {
    dark: { bg: "bg-amber-500/10 group-hover:bg-amber-500/20", icon: "text-amber-400" },
    light: { bg: "bg-amber-50 group-hover:bg-amber-100", icon: "text-amber-600" },
  },
};

export function QuickActions() {
  const { theme } = useTheme();
  const { t } = useLanguage();
  const isDark = theme === "dark";
  const ACTIONS = useActions();

  return (
    <div
      className={cn(
        "rounded-xl border p-6 transition-colors duration-300 h-full",
        isDark
          ? "border-border bg-white/[0.02]"
          : "border-border bg-white shadow-sm"
      )}
    >
      <h3
        className={cn(
          "text-lg font-semibold mb-4",
          isDark ? "text-text-primary" : "text-text-primary"
        )}
      >
        {t("dashboard.home.quickActions")}
      </h3>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {ACTIONS.map((action) => {
          const colors = COLOR_CLASSES[action.color][isDark ? "dark" : "light"];
          return (
            <Link
              key={action.href}
              href={action.href}
              className={cn(
                "group flex items-center gap-4 rounded-lg p-4 transition-all duration-200",
                isDark ? "hover:bg-white/[0.04]" : "hover:bg-surface-hover"
              )}
            >
              <div
                className={cn(
                  "h-10 w-10 rounded-lg flex items-center justify-center shrink-0 transition-colors",
                  colors.bg
                )}
              >
                <action.icon className={cn("h-5 w-5", colors.icon)} />
              </div>
              <div className="flex-1 min-w-0">
                <p
                  className={cn(
                    "text-sm font-medium",
                    isDark ? "text-text-primary" : "text-text-primary"
                  )}
                >
                  {action.title}
                </p>
                <p
                  className={cn(
                    "text-xs truncate",
                    isDark ? "text-text-muted" : "text-text-secondary"
                  )}
                >
                  {action.description}
                </p>
              </div>
              <ArrowRight
                className={cn(
                  "h-4 w-4 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all",
                  isDark ? "text-text-secondary" : "text-text-muted"
                )}
              />
            </Link>
          );
        })}
      </div>
    </div>
  );
}

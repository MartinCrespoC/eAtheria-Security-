"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Clock, ArrowRight, Scan } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";

interface AnalysisRow {
  id: string;
  status: string;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  createdAt: Date;
  appVersion: {
    version: string;
    application: { name: string };
  };
}

const STATUS_VARIANT: Record<string, "success" | "warning" | "destructive" | "info" | "default"> = {
  COMPLETED: "success",
  SCANNING: "info",
  VALIDATING: "info",
  PENDING: "default",
  FAILED: "destructive",
  CANCELLED: "warning",
};

export function RecentAnalyses({ analyses }: { analyses: AnalysisRow[] }) {
  const { theme } = useTheme();
  const { t } = useLanguage();
  const isDark = theme === "dark";

  return (
    <div className={cn(
      "rounded-xl border p-6 transition-colors duration-300",
      isDark ? "border-border bg-white/[0.02]" : "border-border bg-white shadow-sm"
    )}>
      <div className="flex items-center justify-between mb-6">
        <h3 className={cn("text-lg font-semibold", isDark ? "text-text-primary" : "text-text-primary")}>{t("dashboard.home.recentAnalyses")}</h3>
        <Link
          href="/dashboard/analyses"
          className={cn("text-sm flex items-center gap-1 transition-colors", isDark ? "text-accent hover:text-accent" : "text-cyan-600 hover:text-cyan-700")}
        >
          {t("dashboard.home.viewAll")} <ArrowRight className="h-3 w-3" />
        </Link>
      </div>

      {analyses.length === 0 ? (
        <div className={cn("flex flex-col items-center justify-center h-40 gap-3", isDark ? "text-text-muted" : "text-text-secondary")}>
          <Scan className="h-10 w-10 opacity-30" />
          <span className="text-sm">{t("dashboard.home.noVulns")}</span>
        </div>
      ) : (
        <div className="space-y-2">
          {analyses.map((a) => (
            <Link
              key={a.id}
              href={`/dashboard/analyses/${a.id}`}
              className={cn(
                "flex items-center justify-between rounded-lg p-3 transition-colors group",
                isDark ? "hover:bg-white/[0.04]" : "hover:bg-surface-hover"
              )}
            >
              <div className="min-w-0 flex-1">
                <p className={cn("text-sm font-medium truncate transition-colors", isDark ? "text-text-primary group-hover:text-accent" : "text-text-primary group-hover:text-cyan-600")}>
                  {a.appVersion.application.name}{" "}
                  <span className={cn(isDark ? "text-text-muted" : "text-text-secondary")}>v{a.appVersion.version}</span>
                </p>
                <div className={cn("flex items-center gap-2 mt-1 text-xs", isDark ? "text-text-muted" : "text-text-secondary")}>
                  <Clock className="h-3 w-3" />
                  {new Date(a.createdAt).toLocaleDateString("es-ES", {
                    day: "2-digit",
                    month: "short",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </div>
              </div>

              <div className="flex items-center gap-2 ml-3">
                {a.criticalCount > 0 && (
                  <Badge variant="critical">{a.criticalCount} Crit</Badge>
                )}
                {a.highCount > 0 && (
                  <Badge variant="warning">{a.highCount} High</Badge>
                )}
                <Badge variant={STATUS_VARIANT[a.status] ?? "default"}>
                  {a.status}
                </Badge>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

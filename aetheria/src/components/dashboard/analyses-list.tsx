"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Clock, Scan, CheckCircle2, XCircle, Loader2, Timer } from "lucide-react";

interface AnalysisData {
  id: string;
  status: string;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  duration: number | null;
  createdAt: Date;
  completedAt: Date | null;
  appVersion: {
    version: string;
    application: { id: string; name: string };
  };
}

const STATUS_CONFIG: Record<string, { variant: "success" | "warning" | "destructive" | "info" | "default"; icon: typeof CheckCircle2 }> = {
  COMPLETED: { variant: "success", icon: CheckCircle2 },
  SCANNING: { variant: "info", icon: Loader2 },
  VALIDATING: { variant: "info", icon: Loader2 },
  INITIALIZING: { variant: "info", icon: Loader2 },
  PENDING: { variant: "default", icon: Timer },
  FAILED: { variant: "destructive", icon: XCircle },
  CANCELLED: { variant: "warning", icon: XCircle },
};

export function AnalysesList({ analyses }: { analyses: AnalysisData[] }) {
  if (analyses.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-text-muted">
        <Scan className="h-12 w-12 mb-3 opacity-40" />
        <p className="text-lg font-medium">Sin análisis</p>
        <p className="text-sm mt-1">
          Ejecuta un análisis desde una aplicación
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-card overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border">
            <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">
              Aplicación
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">
              Estado
            </th>
            <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">
              Issues
            </th>
            <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">
              Crit
            </th>
            <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">
              High
            </th>
            <th className="px-4 py-3 text-right text-xs font-medium text-text-muted uppercase">
              Fecha
            </th>
          </tr>
        </thead>
        <tbody>
          {analyses.map((a) => {
            const config = STATUS_CONFIG[a.status] || STATUS_CONFIG.PENDING;
            const StatusIcon = config.icon;
            return (
              <tr
                key={a.id}
                className="border-b border-border hover:bg-surface transition-colors"
              >
                <td className="px-4 py-3">
                  <Link
                    href={`/dashboard/analyses/${a.id}`}
                    className="text-sm font-medium text-text-primary hover:text-accent transition-colors"
                  >
                    {a.appVersion.application.name}
                    <span className="text-text-muted ml-1">
                      v{a.appVersion.version}
                    </span>
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <Badge variant={config.variant} className="gap-1">
                    <StatusIcon className="h-3 w-3" />
                    {a.status}
                  </Badge>
                </td>
                <td className="px-4 py-3 text-center text-sm text-text-primary">
                  {a.totalIssues}
                </td>
                <td className="px-4 py-3 text-center">
                  {a.criticalCount > 0 ? (
                    <span className="text-sm font-medium text-red-400">
                      {a.criticalCount}
                    </span>
                  ) : (
                    <span className="text-sm text-text-muted">0</span>
                  )}
                </td>
                <td className="px-4 py-3 text-center">
                  {a.highCount > 0 ? (
                    <span className="text-sm font-medium text-orange-400">
                      {a.highCount}
                    </span>
                  ) : (
                    <span className="text-sm text-text-muted">0</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1.5 text-xs text-text-muted">
                    <Clock className="h-3 w-3" />
                    {new Date(a.createdAt).toLocaleDateString("es-ES", {
                      day: "2-digit",
                      month: "short",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

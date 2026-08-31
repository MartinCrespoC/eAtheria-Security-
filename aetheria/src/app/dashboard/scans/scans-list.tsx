"use client";

import { useState } from "react";
import Link from "next/link";
import { Shield, Clock, AlertTriangle, CheckCircle2, XCircle, Loader2, Filter } from "lucide-react";

interface Scan {
  id: string;
  status: string;
  createdAt: Date;
  completedAt: Date | null;
  duration: number | null;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scanTypes: string[] | Record<string, unknown>;
  appName: string;
  appSlug: string;
  version: string;
  branch: string | null;
  source: string;
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    PENDING: { color: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20", icon: <Clock className="w-3 h-3" />, label: "Queued" },
    INITIALIZING: { color: "bg-blue-500/10 text-blue-400 border-blue-500/20", icon: <Loader2 className="w-3 h-3 animate-spin" />, label: "Initializing" },
    SCANNING: { color: "bg-cyan-500/10 text-accent border-cyan-500/20", icon: <Loader2 className="w-3 h-3 animate-spin" />, label: "Scanning" },
    VALIDATING: { color: "bg-purple-500/10 text-purple-400 border-purple-500/20", icon: <Loader2 className="w-3 h-3 animate-spin" />, label: "Validating" },
    COMPLETED: { color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: <CheckCircle2 className="w-3 h-3" />, label: "Completed" },
    FAILED: { color: "bg-red-500/10 text-red-400 border-red-500/20", icon: <XCircle className="w-3 h-3" />, label: "Failed" },
    CANCELLED: { color: "bg-slate-500/10 text-text-secondary border-slate-500/20", icon: <XCircle className="w-3 h-3" />, label: "Cancelled" },
  };

  const c = config[status] || config.PENDING;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border ${c.color}`}>
      {c.icon} {c.label}
    </span>
  );
}

function SeverityPill({ count, severity }: { count: number; severity: string }) {
  if (count === 0) return null;
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500/20 text-red-300",
    HIGH: "bg-orange-500/20 text-orange-300",
    MEDIUM: "bg-yellow-500/20 text-yellow-300",
    LOW: "bg-blue-500/20 text-blue-300",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full ${colors[severity] || "bg-slate-500/20 text-text-primary"}`}>
      {count} {severity.toLowerCase()}
    </span>
  );
}

function formatDate(d: Date) {
  return new Date(d).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getScanTypesLabel(types: string[] | Record<string, unknown>): string {
  if (Array.isArray(types)) return types.join(", ");
  if (types && typeof types === "object" && "types" in types) {
    return (types.types as string[]).join(", ");
  }
  return "N/A";
}

export function ScansList({ scans }: { scans: Scan[] }) {
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all"
    ? scans
    : scans.filter((s) => s.status === filter);

  const statuses = Array.from(new Set(scans.map((s) => s.status)));

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-4 h-4 text-text-secondary" />
        <button
          onClick={() => setFilter("all")}
          className={`px-3 py-1 text-xs rounded-full border transition-colors ${
            filter === "all"
              ? "bg-cyan-500/20 text-accent border-cyan-500/30"
              : "bg-surface text-text-secondary border-border hover:border-border"
          }`}
        >
          All ({scans.length})
        </button>
        {statuses.map((status) => (
          <button
            key={status}
            onClick={() => setFilter(status)}
            className={`px-3 py-1 text-xs rounded-full border transition-colors ${
              filter === status
                ? "bg-cyan-500/20 text-accent border-cyan-500/30"
                : "bg-surface text-text-secondary border-border hover:border-border"
            }`}
          >
            {status} ({scans.filter((s) => s.status === status).length})
          </button>
        ))}
      </div>

      {/* Scans list */}
      {filtered.length === 0 ? (
        <div className="text-center py-12 text-text-muted">
          <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No scans found</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((scan) => (
            <Link
              key={scan.id}
              href={scan.source === "analysis" ? `/dashboard/analyses/${scan.id}` : "#"}
              className="block bg-surface border border-border rounded-lg p-4 hover:border-border transition-colors"
            >
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <h3 className="text-text-primary font-medium truncate">{scan.appName}</h3>
                    <StatusBadge status={scan.status} />
                  </div>
                  <div className="flex items-center gap-4 text-xs text-text-secondary">
                    <span>{scan.version}</span>
                    {scan.branch && <span className="text-text-muted">branch: {scan.branch}</span>}
                    <span>{formatDate(scan.createdAt)}</span>
                    {scan.duration && <span>{scan.duration}s</span>}
                    <span className="text-text-muted">{getScanTypesLabel(scan.scanTypes)}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {scan.totalIssues > 0 ? (
                    <div className="flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                      <span className="text-sm font-medium text-text-primary">{scan.totalIssues}</span>
                      <div className="flex gap-1 ml-1">
                        <SeverityPill count={scan.criticalCount} severity="CRITICAL" />
                        <SeverityPill count={scan.highCount} severity="HIGH" />
                      </div>
                    </div>
                  ) : scan.status === "COMPLETED" ? (
                    <span className="text-xs text-emerald-400">Clean</span>
                  ) : null}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

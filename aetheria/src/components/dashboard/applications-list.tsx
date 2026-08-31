"use client";

import { useState } from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Plus,
  Search,
  AppWindow,
  GitBranch,
  Clock,
  AlertTriangle,
  ChevronRight,
} from "lucide-react";

interface ApplicationData {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  language: string | null;
  framework: string | null;
  riskLevel: string;
  isActive: boolean;
  lastScanAt: Date | null;
  updatedAt: Date;
  versions: {
    version: string;
    analyses: {
      status: string;
      criticalCount: number;
      highCount: number;
      totalIssues: number;
      createdAt: Date;
    }[];
  }[];
  _count: { versions: number };
}

const RISK_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "default"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "default",
};

export function ApplicationsList({ applications }: { applications: ApplicationData[] }) {
  const [search, setSearch] = useState("");

  const filtered = applications.filter(
    (a) =>
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.language?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            placeholder="Buscar aplicaciones..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-10 w-full rounded-lg border border-border bg-card pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
        <Link href="/dashboard/applications/new">
          <Button variant="cyber" size="sm">
            <Plus className="h-4 w-4 mr-2" /> Nueva App
          </Button>
        </Link>
      </div>

      {/* Grid */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-text-muted">
          <AppWindow className="h-12 w-12 mb-3 opacity-40" />
          <p className="text-lg font-medium">Sin aplicaciones</p>
          <p className="text-sm mt-1">Crea tu primera aplicación para empezar</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map((app) => {
            const lastVersion = app.versions[0];
            const lastAnalysis = lastVersion?.analyses[0];
            return (
              <Link
                key={app.id}
                href={`/dashboard/applications/${app.id}`}
                className="group rounded-xl border border-border bg-card p-5 hover:border-cyan-500/30 hover:bg-surface transition-all"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-border flex items-center justify-center">
                      <AppWindow className="h-5 w-5 text-accent" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-text-primary group-hover:text-accent transition-colors">
                        {app.name}
                      </h3>
                      <div className="flex items-center gap-2 mt-0.5">
                        {app.language && (
                          <span className="text-xs text-text-muted">{app.language}</span>
                        )}
                        {app.framework && (
                          <span className="text-xs text-text-muted">• {app.framework}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <Badge variant={RISK_VARIANT[app.riskLevel] ?? "default"}>
                    {app.riskLevel}
                  </Badge>
                </div>

                {app.description && (
                  <p className="mt-3 text-sm text-text-secondary line-clamp-2">
                    {app.description}
                  </p>
                )}

                <div className="mt-4 flex items-center justify-between text-xs text-text-muted">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1">
                      <GitBranch className="h-3 w-3" />
                      {app._count.versions} ver.
                    </span>
                    {lastAnalysis && (
                      <span className="flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        {lastAnalysis.totalIssues} issues
                      </span>
                    )}
                  </div>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(app.updatedAt).toLocaleDateString("es-ES")}
                  </span>
                </div>

                <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
                  {lastAnalysis ? (
                    <div className="flex items-center gap-2">
                      {lastAnalysis.criticalCount > 0 && (
                        <span className="text-xs font-medium text-red-400">
                          {lastAnalysis.criticalCount} CRIT
                        </span>
                      )}
                      {lastAnalysis.highCount > 0 && (
                        <span className="text-xs font-medium text-orange-400">
                          {lastAnalysis.highCount} HIGH
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-text-muted">Sin análisis</span>
                  )}
                  <ChevronRight className="h-4 w-4 text-text-muted group-hover:text-accent transition-colors" />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

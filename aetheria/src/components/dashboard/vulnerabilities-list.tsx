"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  Search,
  Bug,
  ChevronDown,
  ChevronUp,
  FileCode,
  Shield,
  Wrench,
  ExternalLink,
  Filter,
} from "lucide-react";

interface VulnData {
  id: string;
  severity: string;
  confidence: string;
  category: string;
  title: string;
  description: string;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  codeSnippet: string | null;
  cweId: string | null;
  cveId: string | null;
  owaspTop10: string | null;
  aiValidated: boolean;
  isFalsePositive: boolean;
  smartFix: string | null;
  fixExplanation: string | null;
  status: string;
  createdAt: Date;
  analysis: {
    appVersion: {
      version: string;
      application: { name: string };
    };
  };
}

const SEVERITY_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "default"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "default",
};

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function VulnerabilitiesList({ vulnerabilities }: { vulnerabilities: VulnData[] }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = vulnerabilities
    .filter((v) => {
      if (severityFilter !== "ALL" && v.severity !== severityFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          v.title.toLowerCase().includes(q) ||
          v.category.toLowerCase().includes(q) ||
          v.cweId?.toLowerCase().includes(q) ||
          v.filePath?.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            placeholder="Buscar vulnerabilidades..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-10 w-full rounded-lg border border-border bg-card pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-text-muted" />
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors",
                severityFilter === sev
                  ? "bg-cyan-500/20 text-accent border border-cyan-500/30"
                  : "bg-surface text-text-secondary border border-border hover:text-text-primary"
              )}
            >
              {sev === "ALL" ? "Todas" : sev}
            </button>
          ))}
        </div>
      </div>

      <p className="text-sm text-text-muted">{filtered.length} vulnerabilidades</p>

      {/* List */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-text-muted">
          <Bug className="h-10 w-10 mb-3 opacity-40" />
          <p className="font-medium">Sin resultados</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((v) => {
            const isExpanded = expandedId === v.id;
            return (
              <div
                key={v.id}
                className="rounded-xl border border-border bg-card overflow-hidden transition-all"
              >
                {/* Row header */}
                <button
                  onClick={() => setExpandedId(isExpanded ? null : v.id)}
                  className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-surface transition-colors"
                >
                  <Badge variant={SEVERITY_VARIANT[v.severity] ?? "default"} className="w-20 justify-center">
                    {v.severity}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-text-primary truncate">{v.title}</p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-text-muted">
                      <span>{v.category}</span>
                      {v.cweId && <span className="text-cyan-500/70">{v.cweId}</span>}
                      {v.filePath && (
                        <span className="flex items-center gap-1 truncate max-w-[200px]">
                          <FileCode className="h-3 w-3" />
                          {v.filePath}
                          {v.lineStart && `:${v.lineStart}`}
                        </span>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-text-muted">
                    {v.analysis.appVersion.application.name}
                  </span>
                  <Badge
                    variant={v.status === "OPEN" ? "destructive" : v.status === "RESOLVED" ? "success" : "default"}
                    className="text-[10px]"
                  >
                    {v.status}
                  </Badge>
                  {v.aiValidated && (
                    <Shield className="h-4 w-4 text-emerald-500 shrink-0" />
                  )}
                  {isExpanded ? (
                    <ChevronUp className="h-4 w-4 text-text-muted shrink-0" />
                  ) : (
                    <ChevronDown className="h-4 w-4 text-text-muted shrink-0" />
                  )}
                </button>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-0 border-t border-border space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                      {/* Description */}
                      <div className="space-y-2">
                        <h4 className="text-xs font-semibold uppercase text-text-muted">Descripción</h4>
                        <p className="text-sm text-text-primary leading-relaxed">{v.description}</p>
                      </div>

                      {/* Metadata */}
                      <div className="space-y-3">
                        <h4 className="text-xs font-semibold uppercase text-text-muted">Detalles</h4>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          {v.cweId && (
                            <div>
                              <span className="text-text-muted">CWE:</span>{" "}
                              <a
                                href={`https://cwe.mitre.org/data/definitions/${v.cweId.replace("CWE-", "")}.html`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-accent hover:underline inline-flex items-center gap-1"
                              >
                                {v.cweId}
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            </div>
                          )}
                          {v.cveId && (
                            <div>
                              <span className="text-text-muted">CVE:</span>{" "}
                              <span className="text-text-primary">{v.cveId}</span>
                            </div>
                          )}
                          {v.owaspTop10 && (
                            <div>
                              <span className="text-text-muted">OWASP:</span>{" "}
                              <span className="text-text-primary">{v.owaspTop10}</span>
                            </div>
                          )}
                          <div>
                            <span className="text-text-muted">Confianza:</span>{" "}
                            <span className="text-text-primary">{v.confidence}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Code snippet */}
                    {v.codeSnippet && (
                      <div className="space-y-2">
                        <h4 className="text-xs font-semibold uppercase text-text-muted">Código Afectado</h4>
                        <pre className="rounded-lg bg-background border border-border p-4 text-xs text-text-primary overflow-x-auto">
                          <code>{v.codeSnippet}</code>
                        </pre>
                      </div>
                    )}

                    {/* Smart Fix */}
                    {v.smartFix && (
                      <div className="space-y-2">
                        <h4 className="text-xs font-semibold uppercase text-text-muted flex items-center gap-1">
                          <Wrench className="h-3 w-3" /> Smart Fix
                        </h4>
                        <pre className="rounded-lg bg-emerald-500/10 border border-emerald-600/40 p-4 text-xs text-emerald-800 dark:bg-emerald-950/30 dark:border-emerald-800/30 dark:text-emerald-300 overflow-x-auto">
                          <code>{v.smartFix}</code>
                        </pre>
                        {v.fixExplanation && (
                          <p className="text-sm text-text-secondary">{v.fixExplanation}</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

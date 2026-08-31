"use client";

import { useState } from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ArrowLeft,
  Scan,
  Clock,
  Shield,
  FileCode,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Wrench,
  Bug,
  FileDown,
  FileSpreadsheet,
  Copy,
  Check,
  Download,
} from "lucide-react";
import { exportPdfReport } from "@/lib/export/pdf-report";
import { exportExcelReport } from "@/lib/export/excel-report";

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
  detectionMethod: string | null;
  deltaStatus: string | null;
}

interface AnalysisData {
  id: string;
  status: string;
  startedAt: Date | null;
  completedAt: Date | null;
  duration: number | null;
  errorMessage: string | null;
  scanTypes: unknown;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  falsePositives: number;
  inputTokens: bigint;
  outputTokens: bigint;
  createdAt: Date;
  appVersion: {
    id: string;
    version: string;
    application: { id: string; name: string; slug: string };
  };
  vulnerabilities: VulnData[];
}

const SEV_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "default"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "default",
};

const STATUS_VARIANT: Record<string, "success" | "warning" | "info" | "default" | "destructive"> = {
  COMPLETED: "success",
  IN_PROGRESS: "info",
  SCANNING: "info",
  PENDING: "default",
  FAILED: "destructive",
};

export function AnalysisDetail({ analysis, showInfoFindings = true }: { analysis: AnalysisData; showInfoFindings?: boolean }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const [copiedFix, setCopiedFix] = useState<string | null>(null);

  const scanTypes = Array.isArray(analysis.scanTypes) ? analysis.scanTypes : [];
  const vulns = analysis.vulnerabilities.filter((v) => {
    if (!showInfoFindings && v.severity === "INFO") return false;
    if (filter === "ALL") return true;
    return v.severity === filter;
  });

  const severityCounts = [
    { label: "Críticas", count: analysis.criticalCount, color: "bg-red-500", severity: "CRITICAL" },
    { label: "Altas", count: analysis.highCount, color: "bg-orange-500", severity: "HIGH" },
    { label: "Medias", count: analysis.mediumCount, color: "bg-amber-500", severity: "MEDIUM" },
    { label: "Bajas", count: analysis.lowCount, color: "bg-blue-500", severity: "LOW" },
    { label: "Info", count: analysis.infoCount, color: "bg-slate-500", severity: "INFO" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Link href={`/dashboard/applications/${analysis.appVersion.application.id}`}>
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-text-primary">
                Análisis - {analysis.appVersion.application.name}
              </h1>
              <Badge variant={STATUS_VARIANT[analysis.status] ?? "default"}>
                {analysis.status}
              </Badge>
            </div>
            <p className="text-text-secondary mt-1">
              Versión {analysis.appVersion.version} · {scanTypes.join(", ")}
            </p>
          </div>
        </div>
        {/* Export buttons */}
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportPdfReport(analysis as never)}
            className="gap-1.5"
          >
            <FileDown className="h-3.5 w-3.5" /> PDF
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportExcelReport(analysis as never)}
            className="gap-1.5"
          >
            <FileSpreadsheet className="h-3.5 w-3.5" /> Excel
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { window.open(`/api/analyses/${analysis.id}/sarif`, "_blank"); }}
            className="gap-1.5"
          >
            <Download className="h-3.5 w-3.5" /> SARIF
          </Button>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {severityCounts.map((s) => (
          <button
            key={s.severity}
            onClick={() => setFilter(filter === s.severity ? "ALL" : s.severity)}
            className={`rounded-xl border p-4 text-center transition-all ${
              filter === s.severity
                ? "border-cyan-500/40 bg-cyan-500/5"
                : "border-border bg-card hover:border-border"
            }`}
          >
            <div className={`h-2 w-2 rounded-full ${s.color} mx-auto mb-2`} />
            <p className="text-2xl font-bold text-text-primary">{s.count}</p>
            <p className="text-xs text-text-muted">{s.label}</p>
          </button>
        ))}
      </div>

      {/* Meta info */}
      <div className="flex flex-wrap gap-4 text-sm text-text-secondary">
        {analysis.duration != null && (
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" /> {analysis.duration}s
          </span>
        )}
        <span className="flex items-center gap-1">
          <Scan className="h-3 w-3" /> {analysis.totalIssues} issues
        </span>
        {analysis.falsePositives > 0 && (
          <span>FP: {analysis.falsePositives}</span>
        )}
        <span>
          Tokens: {Number(analysis.inputTokens).toLocaleString()} in / {Number(analysis.outputTokens).toLocaleString()} out
        </span>
        <span>
          {new Date(analysis.createdAt).toLocaleString("es-ES")}
        </span>
      </div>

      {analysis.errorMessage && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {analysis.errorMessage}
        </div>
      )}

      {/* Vulnerabilities */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Bug className="h-4 w-4 text-accent" />
            Vulnerabilidades ({vulns.length})
            {filter !== "ALL" && (
              <Button variant="ghost" size="sm" onClick={() => setFilter("ALL")} className="text-xs">
                Limpiar filtro
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {vulns.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-text-muted">
              <Shield className="h-8 w-8 mb-2 opacity-40" />
              <p>{analysis.totalIssues === 0 ? "Sin vulnerabilidades detectadas" : "Sin resultados para este filtro"}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {vulns.map((v) => {
                const isExpanded = expandedId === v.id;
                return (
                  <div key={v.id} className="rounded-lg border border-border overflow-hidden">
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : v.id)}
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-surface transition-colors"
                    >
                      <Badge variant={SEV_VARIANT[v.severity] ?? "default"} className="w-18 justify-center text-[10px]">
                        {v.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-text-primary truncate">{v.title}</p>
                        <div className="flex items-center gap-2 mt-0.5 text-xs text-text-muted">
                          <span>{v.category}</span>
                          {v.cweId && <span className="text-cyan-500/70">{v.cweId}</span>}
                          {v.filePath && (
                            <span className="flex items-center gap-1 truncate max-w-[180px]">
                              <FileCode className="h-3 w-3" />{v.filePath}{v.lineStart ? `:${v.lineStart}` : ""}
                            </span>
                          )}
                        </div>
                      </div>
                      {v.aiValidated && <Shield className="h-4 w-4 text-emerald-500 shrink-0" />}
                      {v.detectionMethod && (
                        <Badge variant="outline" className="text-[9px] px-1.5 py-0 border-border text-text-secondary">
                          {v.detectionMethod}
                        </Badge>
                      )}
                      {v.deltaStatus === "NEW" && <Badge className="text-[9px] bg-emerald-500/20 text-emerald-400 border-0">NEW</Badge>}
                      {v.deltaStatus === "REOPENED" && <Badge className="text-[9px] bg-amber-500/20 text-amber-400 border-0">REOPENED</Badge>}
                      {v.isFalsePositive && <Badge variant="warning" className="text-[10px]">FP</Badge>}
                      {isExpanded ? <ChevronUp className="h-4 w-4 text-text-muted" /> : <ChevronDown className="h-4 w-4 text-text-muted" />}
                    </button>

                    {isExpanded && (
                      <div className="px-4 pb-4 border-t border-border space-y-4 pt-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <h4 className="text-xs font-semibold uppercase text-text-muted mb-1">Descripción</h4>
                            <p className="text-sm text-text-primary leading-relaxed">{v.description}</p>
                          </div>
                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase text-text-muted">Detalles</h4>
                            <div className="grid grid-cols-2 gap-2 text-sm">
                              {v.cweId && (
                                <div>
                                  <span className="text-text-muted">CWE: </span>
                                  <a href={`https://cwe.mitre.org/data/definitions/${v.cweId.replace("CWE-","")}.html`} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline inline-flex items-center gap-1">
                                    {v.cweId} <ExternalLink className="h-3 w-3" />
                                  </a>
                                </div>
                              )}
                              {v.cveId && <div><span className="text-text-muted">CVE: </span><span className="text-text-primary">{v.cveId}</span></div>}
                              {v.owaspTop10 && <div><span className="text-text-muted">OWASP: </span><span className="text-text-primary">{v.owaspTop10}</span></div>}
                              <div><span className="text-text-muted">Confianza: </span><span className="text-text-primary">{v.confidence}</span></div>
                            </div>
                          </div>
                        </div>

                        {v.codeSnippet && (
                          <div>
                            <h4 className="text-xs font-semibold uppercase text-text-muted mb-1">Código</h4>
                            <pre className="rounded-lg bg-background border border-border p-3 text-xs text-text-primary overflow-x-auto"><code>{v.codeSnippet}</code></pre>
                          </div>
                        )}

                        {v.smartFix && (v.severity === "CRITICAL" || v.severity === "HIGH" || v.severity === "MEDIUM") && (
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <h4 className="text-xs font-semibold uppercase text-text-muted flex items-center gap-1"><Wrench className="h-3 w-3" /> Fix Propuesto por IA</h4>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(v.smartFix || "");
                                  setCopiedFix(v.id);
                                  setTimeout(() => setCopiedFix(null), 2000);
                                }}
                                className="flex items-center gap-1 text-xs text-accent hover:text-accent transition-colors"
                              >
                                {copiedFix === v.id ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                                {copiedFix === v.id ? "Copiado" : "Copiar Fix"}
                              </button>
                            </div>
                            <pre className="rounded-lg bg-emerald-500/10 border border-emerald-600/40 p-3 text-xs text-emerald-800 dark:bg-emerald-950/30 dark:border-emerald-800/30 dark:text-emerald-300 overflow-x-auto"><code>{v.smartFix}</code></pre>
                            {v.fixExplanation && <p className="text-sm text-text-secondary mt-1">{v.fixExplanation}</p>}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

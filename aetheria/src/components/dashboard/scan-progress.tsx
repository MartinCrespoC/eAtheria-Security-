"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  SkipForward,
  Terminal,
  Shield,
  FileSearch,
  Package,
  Bug,
  Filter,
  FileText,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

interface ScanLogEntry {
  timestamp: number;
  level: "info" | "success" | "warning" | "error" | "debug";
  message: string;
  details?: string;
}

interface ScanStep {
  id: string;
  label: string;
  description: string;
  status: "pending" | "running" | "completed" | "skipped" | "error";
  progress: number;
  startedAt?: number;
  completedAt?: number;
  metadata?: Record<string, string | number>;
}

interface ScanProgressState {
  analysisId: string;
  status: "queued" | "running" | "completed" | "failed";
  overallProgress: number;
  currentPhase: string;
  scanLevel: string;
  scanTypes: string[];
  steps: ScanStep[];
  logs: ScanLogEntry[];
  stats: {
    filesDiscovered: number;
    filesAnalyzed: number;
    languagesDetected: string[];
    dependenciesFound: number;
    vulnerabilitiesFound: number;
    falsePositivesDetected: number;
    linesOfCode: number;
  };
  startedAt: number;
  completedAt?: number;
  error?: string;
}

const STEP_ICONS: Record<string, typeof Activity> = {
  discovery: FileSearch,
  sast: Shield,
  sca: Package,
  sbom: FileText,
  dast: Activity,
  "fp-detection": Filter,
  report: Bug,
};

const LOG_COLORS: Record<string, string> = {
  info: "text-text-primary",
  success: "text-emerald-400",
  warning: "text-amber-400",
  error: "text-red-400",
  debug: "text-text-muted",
};

const SCAN_LEVEL_LABELS: Record<string, string> = {
  STATIC: "Estático (L1) — Patrones por archivo",
  LIGHTWEIGHT: "Ligero (L2) — Flujo de datos intra-archivo",
  DEEP: "Profundo (L3) — Taint tracking entre archivos",
};

export function ScanProgress({ analysisId, onComplete }: { analysisId: string; onComplete?: () => void }) {
  const [state, setState] = useState<ScanProgressState | null>(null);
  const [showLogs, setShowLogs] = useState(true);
  const [elapsed, setElapsed] = useState(0);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const connectRef = useRef<() => void>(() => {});

  const connect = useCallback(() => {
    const es = new EventSource(`/api/analyses/${analysisId}/progress`);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as ScanProgressState;
        setState(data);
        if (data.status === "completed" || data.status === "failed") {
          es.close();
          if (data.status === "completed" && onComplete) {
            setTimeout(onComplete, 2000);
          }
        }
      } catch { /* ignore parse errors */ }
    };

    es.onerror = () => {
      es.close();
      setTimeout(() => {
        setState((prev) => {
          if (prev && (prev.status === "completed" || prev.status === "failed")) return prev;
          connectRef.current();
          return prev;
        });
      }, 3000);
    };
  }, [analysisId, onComplete]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    connect();
    return () => { eventSourceRef.current?.close(); };
  }, [connect]);

  // Elapsed timer
  useEffect(() => {
    if (!state || state.status === "completed" || state.status === "failed") return;
    const interval = setInterval(() => {
      setElapsed(Math.round((Date.now() - state.startedAt) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [state?.startedAt, state?.status]);

  // Auto-scroll logs
  useEffect(() => {
    if (showLogs && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [state?.logs.length, showLogs]);

  if (!state) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-accent" />
        <span className="ml-3 text-text-secondary">Conectando al motor de análisis...</span>
      </div>
    );
  }

  const isRunning = state.status === "running" || state.status === "queued";
  const duration = state.completedAt
    ? Math.round((state.completedAt - state.startedAt) / 1000)
    : elapsed;

  return (
    <div className="space-y-6">
      {/* Overall progress bar */}
      <Card className="border-border bg-card">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              {isRunning ? (
                <Loader2 className="h-5 w-5 animate-spin text-accent" />
              ) : state.status === "completed" ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <XCircle className="h-5 w-5 text-red-400" />
              )}
              <div>
                <p className="text-sm font-medium text-text-primary">
                  {state.status === "completed" ? "Análisis completado" : state.status === "failed" ? "Análisis fallido" : state.currentPhase}
                </p>
                <p className="text-xs text-text-muted">
                  {SCAN_LEVEL_LABELS[state.scanLevel] || state.scanLevel || "Estático"} · {(state.scanTypes || []).join(" + ") || "SAST"} · {duration}s
                </p>
              </div>
            </div>
            <span className="text-2xl font-bold text-text-primary tabular-nums">{state.overallProgress}%</span>
          </div>
          <div className="h-2.5 rounded-full bg-surface overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ease-out ${
                state.status === "failed" ? "bg-red-500" : state.status === "completed" ? "bg-emerald-500" : "bg-gradient-to-r from-cyan-500 to-purple-500"
              }`}
              style={{ width: `${state.overallProgress}%` }}
            />
          </div>
          {state.error && (
            <p className="mt-2 text-sm text-red-400">{state.error}</p>
          )}
        </CardContent>
      </Card>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          { label: "Archivos", value: state.stats.filesDiscovered, icon: FileSearch },
          { label: "LOC", value: state.stats.linesOfCode.toLocaleString(), icon: FileText },
          { label: "Lenguajes", value: state.stats.languagesDetected.length, icon: Activity },
          { label: "Dependencias", value: state.stats.dependenciesFound, icon: Package },
          { label: "Hallazgos", value: state.stats.vulnerabilitiesFound, icon: Bug },
          { label: "Falsos Pos.", value: state.stats.falsePositivesDetected, icon: Filter },
          { label: "Tiempo", value: `${duration}s`, icon: Activity },
        ].map((stat) => (
          <div key={stat.label} className="rounded-lg border border-border bg-card p-3 text-center">
            <stat.icon className="h-4 w-4 text-accent/60 mx-auto mb-1" />
            <p className="text-lg font-bold text-text-primary tabular-nums">{stat.value}</p>
            <p className="text-[10px] text-text-muted uppercase tracking-wide">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Languages detected */}
      {state.stats.languagesDetected.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {state.stats.languagesDetected.map((lang) => (
            <Badge key={lang} variant="secondary" className="text-[11px]">{lang}</Badge>
          ))}
        </div>
      )}

      {/* Steps timeline */}
      <Card className="border-border bg-card">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4 text-accent" />
            Fases del Análisis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {state.steps.map((step, idx) => {
              const Icon = STEP_ICONS[step.id] || Circle;
              const isLast = idx === state.steps.length - 1;
              return (
                <div key={step.id} className="flex gap-3">
                  {/* Timeline connector */}
                  <div className="flex flex-col items-center">
                    <div className={`h-8 w-8 rounded-full flex items-center justify-center border ${
                      step.status === "completed" ? "border-emerald-500/40 bg-emerald-500/10" :
                      step.status === "running" ? "border-cyan-500/40 bg-cyan-500/10" :
                      step.status === "error" ? "border-red-500/40 bg-red-500/10" :
                      step.status === "skipped" ? "border-border bg-surface" :
                      "border-border bg-surface"
                    }`}>
                      {step.status === "completed" ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> :
                       step.status === "running" ? <Loader2 className="h-4 w-4 animate-spin text-accent" /> :
                       step.status === "error" ? <XCircle className="h-4 w-4 text-red-400" /> :
                       step.status === "skipped" ? <SkipForward className="h-4 w-4 text-text-muted" /> :
                       <Icon className="h-4 w-4 text-text-muted" />}
                    </div>
                    {!isLast && <div className={`w-px flex-1 min-h-[16px] ${step.status === "completed" ? "bg-emerald-500/30" : "bg-surface"}`} />}
                  </div>

                  {/* Step content */}
                  <div className={`flex-1 pb-4 ${step.status === "pending" ? "opacity-50" : ""}`}>
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-text-primary">{step.label}</p>
                      {step.status === "running" && (
                        <span className="text-xs text-accent tabular-nums">{step.progress}%</span>
                      )}
                      {step.status === "completed" && step.completedAt && step.startedAt && (
                        <span className="text-xs text-text-muted">{Math.round((step.completedAt - step.startedAt) / 1000)}s</span>
                      )}
                    </div>
                    <p className="text-xs text-text-muted mt-0.5">{step.description}</p>
                    {step.status === "running" && (
                      <div className="h-1 rounded-full bg-surface mt-2 overflow-hidden">
                        <div className="h-full rounded-full bg-cyan-500 transition-all duration-500" style={{ width: `${step.progress}%` }} />
                      </div>
                    )}
                    {step.metadata && Object.keys(step.metadata).length > 0 && (
                      <div className="flex gap-2 mt-1.5">
                        {Object.entries(step.metadata).map(([k, v]) => (
                          <span key={k} className="text-[10px] text-text-muted bg-surface rounded px-1.5 py-0.5">
                            {k}: {v}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Real-time logs */}
      <Card className="border-border bg-card">
        <CardHeader className="pb-2">
          <button
            onClick={() => setShowLogs(!showLogs)}
            className="flex items-center justify-between w-full"
          >
            <CardTitle className="text-base flex items-center gap-2">
              <Terminal className="h-4 w-4 text-accent" />
              Logs en Tiempo Real
              <Badge variant="secondary" className="text-[10px]">{state.logs.length}</Badge>
            </CardTitle>
            {showLogs ? <ChevronUp className="h-4 w-4 text-text-muted" /> : <ChevronDown className="h-4 w-4 text-text-muted" />}
          </button>
        </CardHeader>
        {showLogs && (
          <CardContent>
            <div className="h-64 overflow-y-auto rounded-lg bg-background border border-border p-3 font-mono text-xs space-y-0.5">
              {state.logs.map((log, i) => (
                <div key={i} className={`flex gap-2 ${LOG_COLORS[log.level] || "text-text-primary"}`}>
                  <span className="text-text-muted shrink-0 tabular-nums">
                    {new Date(log.timestamp).toLocaleTimeString("es-ES", { hour12: false })}
                  </span>
                  <span className="shrink-0 uppercase w-12 text-[10px] pt-0.5 opacity-60">{log.level}</span>
                  <span>{log.message}</span>
                </div>
              ))}
              {isRunning && (
                <div className="flex items-center gap-1 text-accent animate-pulse">
                  <span className="text-text-muted">▊</span>
                </div>
              )}
              <div ref={logsEndRef} />
            </div>
          </CardContent>
        )}
      </Card>

      {/* Auditor info */}
      <Card className="border-border bg-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4 text-accent" />
            Información de Auditoría
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-text-muted">Nivel de escaneo</span>
                <span className="text-text-primary">{SCAN_LEVEL_LABELS[state.scanLevel]?.split("—")[0] || state.scanLevel}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Metodología</span>
                <span className="text-text-primary">{state.scanLevel === "DEEP" ? "Taint tracking + data-flow" : state.scanLevel === "LIGHTWEIGHT" ? "Data-flow intra-archivo" : "Pattern matching"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Motores</span>
                <span className="text-text-primary">{(state.scanTypes || []).join(", ") || "SAST"}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-text-muted">Base de conocimiento FP</span>
                <span className="text-text-primary">195+ reglas / 13 lenguajes</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Estándares</span>
                <span className="text-text-primary">OWASP Top 10 · MITRE CWE Top 25</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">SBOM</span>
                <span className="text-text-primary">CycloneDX 1.5</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

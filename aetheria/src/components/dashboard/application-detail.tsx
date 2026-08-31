"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ArrowLeft,
  Plus,
  Loader2,
  GitBranch,
  FileCode,
  Scan,
  AlertTriangle,
  Clock,
  Upload,
} from "lucide-react";

interface AnalysisSummary {
  id: string;
  status: string;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  createdAt: Date;
  completedAt: Date | null;
}

interface VersionData {
  id: string;
  version: string;
  branch: string | null;
  commitHash: string | null;
  sourceType: string;
  linesOfCode: number | null;
  createdAt: Date;
  analyses: AnalysisSummary[];
}

interface AppData {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  repoUrl: string | null;
  language: string | null;
  framework: string | null;
  riskLevel: string;
  isActive: boolean;
  createdAt: Date;
  versions: VersionData[];
}

const STATUS_VARIANT: Record<string, "success" | "warning" | "info" | "default" | "destructive"> = {
  COMPLETED: "success",
  IN_PROGRESS: "info",
  SCANNING: "info",
  VALIDATING: "info",
  PENDING: "default",
  FAILED: "destructive",
  CANCELLED: "warning",
};

const LEVEL_ORDER = ["STATIC", "LIGHTWEIGHT", "DEEP"] as const;
type Level = (typeof LEVEL_ORDER)[number];
const LEVEL_LABELS: Record<Level, string> = {
  STATIC: "L1 — Estático",
  LIGHTWEIGHT: "L2 — Ligero",
  DEEP: "L3 — Profundo",
};

export function ApplicationDetail({ application, defaultScanLevel = "STATIC" }: { application: AppData; defaultScanLevel?: string }) {
  const router = useRouter();
  const [showVersionForm, setShowVersionForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState<string | null>(null);
  const [error, setError] = useState("");
  const maxLevel: Level = "DEEP";
  const initialLevel: Level = (LEVEL_ORDER.includes(defaultScanLevel as Level) && LEVEL_ORDER.indexOf(defaultScanLevel as Level) <= LEVEL_ORDER.indexOf(maxLevel))
    ? (defaultScanLevel as Level)
    : maxLevel;
  const [scanLevel, setScanLevel] = useState<Level>(initialLevel);
  const [versionForm, setVersionForm] = useState({
    version: "",
    branch: "",
    sourceType: "ZIP_UPLOAD" as string,
  });

  const handleCreateVersion = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`/api/applications/${application.id}/versions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(versionForm),
      });
      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Error al crear versión");
        return;
      }
      setShowVersionForm(false);
      setVersionForm({ version: "", branch: "", sourceType: "ZIP_UPLOAD" });
      router.refresh();
    } catch {
      setError("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  const handleStartAnalysis = async (versionId: string) => {
    setAnalyzing(versionId);
    setError("");
    try {
      const res = await fetch("/api/analyses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          appVersionId: versionId,
          scanTypes: ["SAST", "SCA"],
          scanLevel,
        }),
      });
      if (res.ok) {
        router.refresh();
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || `Error al iniciar el análisis (HTTP ${res.status})`);
      }
    } catch {
      setError("Error de conexión al iniciar el análisis");
    } finally {
      setAnalyzing(null);
    }
  };

  const totalAnalyses = application.versions.reduce(
    (sum, v) => sum + v.analyses.length, 0
  );
  const totalVulns = application.versions.reduce(
    (sum, v) => sum + v.analyses.reduce((s, a) => s + a.totalIssues, 0), 0
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard/applications">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-text-primary">{application.name}</h1>
              <Badge variant={application.isActive ? "success" : "default"}>
                {application.isActive ? "Activa" : "Inactiva"}
              </Badge>
              <Badge variant="secondary">{application.riskLevel}</Badge>
            </div>
            {application.description && (
              <p className="text-text-secondary mt-1">{application.description}</p>
            )}
          </div>
        </div>
      </div>

      {/* Global error banner (analysis start / license limits) */}
      {error && !showVersionForm && (
        <div className="flex items-start justify-between gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-medium text-red-300">No se pudo iniciar el análisis</p>
              <p className="text-sm text-red-400/90 mt-0.5">{error}</p>
            </div>
          </div>
          <button onClick={() => setError("")} className="text-red-400/70 hover:text-red-300 text-lg leading-none shrink-0" aria-label="Cerrar">×</button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <GitBranch className="h-5 w-5 text-accent" />
              <div>
                <p className="text-xs text-text-muted">Versiones</p>
                <p className="text-xl font-bold text-text-primary">{application.versions.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Scan className="h-5 w-5 text-purple-400" />
              <div>
                <p className="text-xs text-text-muted">Análisis</p>
                <p className="text-xl font-bold text-text-primary">{totalAnalyses}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-400" />
              <div>
                <p className="text-xs text-text-muted">Vulnerabilidades</p>
                <p className="text-xl font-bold text-text-primary">{totalVulns}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <FileCode className="h-5 w-5 text-emerald-400" />
              <div>
                <p className="text-xs text-text-muted">Lenguaje</p>
                <p className="text-sm font-medium text-text-primary">
                  {application.language || "—"}
                  {application.framework && ` / ${application.framework}`}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Versions */}
      <Card className="border-border bg-card">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Versiones</CardTitle>
          <Button variant="cyber" size="sm" onClick={() => setShowVersionForm(!showVersionForm)}>
            <Plus className="h-4 w-4 mr-2" /> Nueva Versión
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Version create form */}
          {showVersionForm && (
            <div className="rounded-lg border border-border bg-surface p-4">
              <form onSubmit={handleCreateVersion} className="space-y-4">
                {error && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                    {error}
                  </div>
                )}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label>Versión</Label>
                    <Input
                      placeholder="1.0.0"
                      value={versionForm.version}
                      onChange={(e) => setVersionForm({ ...versionForm, version: e.target.value })}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Branch</Label>
                    <Input
                      placeholder="main"
                      value={versionForm.branch}
                      onChange={(e) => setVersionForm({ ...versionForm, branch: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Tipo de Fuente</Label>
                    <select
                      value={versionForm.sourceType}
                      onChange={(e) => setVersionForm({ ...versionForm, sourceType: e.target.value })}
                      className="h-10 w-full rounded-lg border border-border bg-card px-3 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                    >
                      <option value="ZIP_UPLOAD">Subir archivo</option>
                      <option value="GITHUB">GitHub</option>
                      <option value="URL">URL</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-2 justify-end">
                  <Button variant="ghost" type="button" onClick={() => setShowVersionForm(false)}>
                    Cancelar
                  </Button>
                  <Button variant="cyber" type="submit" disabled={loading}>
                    {loading && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
                    Crear Versión
                  </Button>
                </div>
              </form>
            </div>
          )}

          {/* Versions list */}
          {application.versions.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-text-muted">
              <GitBranch className="h-8 w-8 mb-2 opacity-40" />
              <p>Sin versiones. Crea una para comenzar el análisis.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {application.versions.map((v) => (
                <div
                  key={v.id}
                  className="rounded-lg border border-border bg-surface p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center">
                        <GitBranch className="h-4 w-4 text-accent" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-text-primary">v{v.version}</span>
                          {v.branch && (
                            <Badge variant="secondary" className="text-[10px]">{v.branch}</Badge>
                          )}
                          <Badge variant="default" className="text-[10px]">{v.sourceType}</Badge>
                        </div>
                        <div className="flex items-center gap-3 mt-0.5 text-xs text-text-muted">
                          {v.commitHash && <span className="font-mono">{v.commitHash.slice(0, 7)}</span>}
                          {v.linesOfCode && <span>{v.linesOfCode.toLocaleString()} LOC</span>}
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(v.createdAt).toLocaleDateString("es-ES")}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <select
                        value={scanLevel}
                        onChange={(e) => setScanLevel(e.target.value as Level)}
                        title="Nivel de escaneo"
                        className="h-8 rounded-lg border border-border bg-card px-2 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                      >
                        {LEVEL_ORDER.map((lvl) => {
                          const locked = LEVEL_ORDER.indexOf(lvl) > LEVEL_ORDER.indexOf(maxLevel);
                          return (
                            <option key={lvl} value={lvl} disabled={locked}>
                              {LEVEL_LABELS[lvl]}{locked ? " 🔒" : ""}
                            </option>
                          );
                        })}
                      </select>
                      <Button
                        variant="cyber"
                        size="sm"
                        onClick={() => handleStartAnalysis(v.id)}
                        disabled={analyzing === v.id}
                      >
                        {analyzing === v.id ? (
                          <Loader2 className="h-3 w-3 animate-spin mr-1" />
                        ) : (
                          <Scan className="h-3 w-3 mr-1" />
                        )}
                        Analizar
                      </Button>
                      {v.sourceType === "ZIP_UPLOAD" && (
                        <Button variant="outline" size="sm" asChild>
                          <Link href={`/dashboard/applications/${application.id}/versions/${v.id}/upload`}>
                            <Upload className="h-3 w-3 mr-1" /> Subir archivo
                          </Link>
                        </Button>
                      )}
                    </div>
                  </div>

                  {/* Version analyses */}
                  {v.analyses.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      {v.analyses.map((a) => (
                        <Link
                          key={a.id}
                          href={`/dashboard/analyses/${a.id}`}
                          className="flex items-center justify-between rounded-md bg-card px-3 py-2 hover:bg-surface transition-colors"
                        >
                          <div className="flex items-center gap-2">
                            <Badge variant={STATUS_VARIANT[a.status] ?? "default"} className="text-[10px]">
                              {a.status}
                            </Badge>
                            <span className="text-xs text-text-secondary">
                              {new Date(a.createdAt).toLocaleString("es-ES")}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-xs">
                            {a.criticalCount > 0 && (
                              <span className="text-red-400">{a.criticalCount} críticas</span>
                            )}
                            {a.highCount > 0 && (
                              <span className="text-orange-400">{a.highCount} altas</span>
                            )}
                            <span className="text-text-muted">{a.totalIssues} total</span>
                          </div>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

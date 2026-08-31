"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Search, CheckCircle, XCircle, HelpCircle, Upload, Loader2 } from "lucide-react";

interface TriageResult {
  id: string;
  title: string;
  sourceType: string;
  verdict: "confirmed" | "not_actionable" | "needs_review";
  confidence: string | null;
  exploitRank: number | null;
  evidence: string | null;
  counterevidence: string | null;
  recommendedNext: string | null;
  createdAt: string;
}

const VERDICT_CONFIG = {
  confirmed: { icon: CheckCircle, color: "text-red-600", bg: "bg-red-50 dark:bg-red-950/30", label: "Confirmado" },
  not_actionable: { icon: XCircle, color: "text-green-600", bg: "bg-green-50 dark:bg-green-950/30", label: "No Accionable" },
  needs_review: { icon: HelpCircle, color: "text-yellow-600", bg: "bg-yellow-50 dark:bg-yellow-950/30", label: "Requiere Revisión" },
};

export function TriagePanel({ initialResults }: { initialResults?: TriageResult[] }) {
  const [results, setResults] = useState<TriageResult[]>(initialResults || []);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<string>("all");
  const [error, setError] = useState<string | null>(null);

  const filtered = filter === "all" ? results : results.filter((r) => r.verdict === filter);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const title = formData.get("title") as string;
    const description = formData.get("description") as string;
    const sourceType = formData.get("sourceType") as string;

    if (!title.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [{ title, description, sourceType }],
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error en triage");
      }

      const data = await res.json();
      // Refresh results
      const refreshRes = await fetch("/api/triage");
      if (refreshRes.ok) {
        setResults(await refreshRes.json());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error desconocido");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <div className="rounded-lg border p-4">
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <Upload className="h-4 w-4" />
          Triaje de Finding Externo
        </h3>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="grid gap-3 md:grid-cols-[1fr_auto]">
            <input
              name="title"
              placeholder="Título del finding (ej: SQL Injection in /api/users)"
              className="rounded-md border px-3 py-2 text-sm w-full bg-background"
              required
            />
            <select
              name="sourceType"
              className="rounded-md border px-3 py-2 text-sm bg-background"
              defaultValue="freeform"
            >
              <option value="sarif">SARIF</option>
              <option value="cve">CVE</option>
              <option value="advisory">Advisory</option>
              <option value="scanner_ticket">Scanner Ticket</option>
              <option value="bug_bounty">Bug Bounty</option>
              <option value="freeform">Freeform</option>
            </select>
          </div>
          <textarea
            name="description"
            placeholder="Descripción, componente afectado, CWE, referencias..."
            className="rounded-md border px-3 py-2 text-sm w-full bg-background min-h-[80px]"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            {loading ? "Analizando..." : "Triaje"}
          </button>
        </form>
        {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2">
        {["all", "confirmed", "needs_review", "not_actionable"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              "px-3 py-1 rounded-full text-xs font-medium transition-colors",
              filter === f ? "bg-primary text-primary-foreground" : "bg-muted hover:bg-muted/80"
            )}
          >
            {f === "all" ? "Todos" : VERDICT_CONFIG[f as keyof typeof VERDICT_CONFIG]?.label || f}
            <span className="ml-1 opacity-70">
              ({f === "all" ? results.length : results.filter((r) => r.verdict === f).length})
            </span>
          </button>
        ))}
      </div>

      {/* Results List */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
            Sin resultados de triaje. Importa findings externos para comenzar.
          </div>
        ) : (
          filtered.map((result) => {
            const config = VERDICT_CONFIG[result.verdict];
            const Icon = config.icon;
            return (
              <div key={result.id} className={cn("rounded-lg border p-4", config.bg)}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Icon className={cn("h-4 w-4", config.color)} />
                      <p className="font-medium text-sm">{result.title}</p>
                      {result.exploitRank && (
                        <Badge variant="outline" className="text-xs">#{result.exploitRank}</Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="secondary" className="text-xs">{result.sourceType}</Badge>
                      {result.confidence && (
                        <span className="text-xs text-muted-foreground">Confianza: {result.confidence}</span>
                      )}
                    </div>
                    {result.evidence && (
                      <p className="text-xs text-muted-foreground mt-2 line-clamp-2">{result.evidence}</p>
                    )}
                    {result.recommendedNext && (
                      <p className="text-xs mt-1 italic text-muted-foreground">→ {result.recommendedNext}</p>
                    )}
                  </div>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(result.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Wrench, ChevronDown, ChevronUp, Star, Loader2 } from "lucide-react";

interface HardeningOption {
  optionId: string;
  title: string;
  kind: string;
  summary: string;
  tradeoffs: Record<string, string>;
  residualRisks: string;
}

interface HardeningProposal {
  id: string;
  title: string;
  opportunityId: string;
  diagnosis: string;
  options: HardeningOption[];
  recommended: string | null;
  createdAt: string;
}

const TRADEOFF_COLORS: Record<string, string> = {
  improved: "text-green-600",
  neutral: "text-gray-500",
  "slight-cost": "text-yellow-600",
  "significant-cost": "text-red-600",
};

const KIND_LABELS: Record<string, string> = {
  architectural: "Arquitectural",
  library: "Librería",
  process: "Proceso",
  configuration: "Configuración",
  testing: "Testing",
};

export function HardeningPortfolio({
  analysisId,
  initialProposals,
}: {
  analysisId?: string;
  initialProposals?: HardeningProposal[];
}) {
  const [proposals, setProposals] = useState<HardeningProposal[]>(initialProposals || []);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    if (!analysisId) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/analyses/${analysisId}/hardening`, { method: "POST" });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Error generando propuestas");
      }
      // Refresh
      const refreshRes = await fetch(`/api/analyses/${analysisId}/hardening`);
      if (refreshRes.ok) {
        setProposals(await refreshRes.json());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error desconocido");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Generate Button */}
      {analysisId && (
        <div className="flex items-center gap-3">
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
            {loading ? "Generando..." : "Generar Propuestas de Hardening"}
          </button>
          {error && <span className="text-sm text-red-600">{error}</span>}
        </div>
      )}

      {/* Proposals List */}
      {proposals.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
          <Wrench className="mx-auto h-10 w-10 mb-3 opacity-50" />
          <p>Sin propuestas de hardening</p>
          <p className="mt-1">Genera propuestas estructurales basadas en los hallazgos del análisis</p>
        </div>
      ) : (
        proposals.map((proposal) => (
          <div key={proposal.id} className="rounded-lg border">
            <button
              onClick={() => setExpandedId(expandedId === proposal.id ? null : proposal.id)}
              className="flex w-full items-center justify-between p-4 text-left hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Badge variant="outline" className="text-xs font-mono">{proposal.opportunityId}</Badge>
                <div>
                  <p className="font-medium text-sm">{proposal.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{proposal.diagnosis}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-xs">
                  {proposal.options?.length || 0} opciones
                </Badge>
                {expandedId === proposal.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </div>
            </button>

            {expandedId === proposal.id && (
              <div className="border-t p-4 space-y-4">
                {/* Diagnosis */}
                <div className="rounded-md bg-muted/50 p-3">
                  <p className="text-xs font-medium text-muted-foreground mb-1">DIAGNÓSTICO</p>
                  <p className="text-sm">{proposal.diagnosis}</p>
                </div>

                {/* Options */}
                <div className="space-y-3">
                  {proposal.options?.map((opt) => (
                    <div
                      key={opt.optionId}
                      className={cn(
                        "rounded-md border p-3",
                        proposal.recommended === opt.optionId && "border-primary ring-1 ring-primary/20"
                      )}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-mono text-xs text-muted-foreground">{opt.optionId}</span>
                        <p className="font-medium text-sm">{opt.title}</p>
                        <Badge variant="outline" className="text-xs">{KIND_LABELS[opt.kind] || opt.kind}</Badge>
                        {proposal.recommended === opt.optionId && (
                          <span className="inline-flex items-center gap-1 text-xs text-primary font-medium">
                            <Star className="h-3 w-3 fill-current" /> Recomendada
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mb-3">{opt.summary}</p>

                      {/* Tradeoffs Table */}
                      {opt.tradeoffs && (
                        <div className="grid grid-cols-3 md:grid-cols-6 gap-2 text-xs">
                          {Object.entries(opt.tradeoffs).map(([dim, val]) => (
                            <div key={dim} className="text-center">
                              <p className="text-muted-foreground capitalize">{dim}</p>
                              <p className={cn("font-medium", TRADEOFF_COLORS[val] || "text-gray-500")}>
                                {val === "improved" ? "↑" : val === "neutral" ? "→" : val === "slight-cost" ? "↓" : "↓↓"}
                              </p>
                            </div>
                          ))}
                        </div>
                      )}

                      {opt.residualRisks && (
                        <p className="text-xs text-muted-foreground mt-2 italic">
                          Riesgo residual: {opt.residualRisks}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}

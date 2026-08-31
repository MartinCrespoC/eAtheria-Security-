"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { GitBranch, Target, Scale, AlertCircle } from "lucide-react";

interface AttackPathData {
  attackPathDataflow?: string | null;
  attackPathReachability?: string | null;
  severityRationale?: string | null;
  severityChangeConditions?: string | null;
  impactLevel?: string | null;
  likelihoodLevel?: string | null;
  rootCauseSummary?: string | null;
  counterevidence?: string | null;
  proofGaps?: string | null;
  validationMethod?: string | null;
  validationConfidence?: number | null;
}

const LEVEL_COLORS: Record<string, string> = {
  high: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
  low: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
  ignore: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
};

export function AttackPathView({ data }: { data: AttackPathData }) {
  const hasData = data.attackPathDataflow || data.severityRationale || data.impactLevel;

  if (!hasData) {
    return (
      <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
        <GitBranch className="mx-auto h-8 w-8 mb-2 opacity-50" />
        Sin análisis de ruta de ataque — disponible en escaneos LIGHTWEIGHT/DEEP
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Impact × Likelihood */}
      {(data.impactLevel || data.likelihoodLevel) && (
        <div className="flex items-center gap-4 rounded-lg border p-4">
          <Scale className="h-5 w-5 text-muted-foreground" />
          <div className="flex items-center gap-3">
            <div className="text-center">
              <p className="text-xs text-muted-foreground">Impacto</p>
              <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-bold uppercase", LEVEL_COLORS[data.impactLevel || ""] || "bg-gray-100")}>
                {data.impactLevel || "N/A"}
              </span>
            </div>
            <span className="text-muted-foreground">×</span>
            <div className="text-center">
              <p className="text-xs text-muted-foreground">Probabilidad</p>
              <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-bold uppercase", LEVEL_COLORS[data.likelihoodLevel || ""] || "bg-gray-100")}>
                {data.likelihoodLevel || "N/A"}
              </span>
            </div>
          </div>
          {data.validationConfidence != null && (
            <div className="ml-auto text-right">
              <p className="text-xs text-muted-foreground">Confianza</p>
              <p className="text-sm font-bold">{Math.round(data.validationConfidence * 100)}%</p>
            </div>
          )}
        </div>
      )}

      {/* Dataflow */}
      {data.attackPathDataflow && (
        <div className="rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-2">
            <GitBranch className="h-4 w-4 text-blue-500" />
            <h4 className="text-sm font-medium">Dataflow (Source → Control → Sink)</h4>
          </div>
          <p className="text-sm text-muted-foreground whitespace-pre-wrap font-mono bg-muted/50 rounded p-3">
            {data.attackPathDataflow}
          </p>
        </div>
      )}

      {/* Reachability */}
      {data.attackPathReachability && (
        <div className="rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-2">
            <Target className="h-4 w-4 text-purple-500" />
            <h4 className="text-sm font-medium">Alcanzabilidad</h4>
          </div>
          <p className="text-sm text-muted-foreground">{data.attackPathReachability}</p>
        </div>
      )}

      {/* Severity Rationale */}
      {data.severityRationale && (
        <div className="rounded-lg border p-4">
          <h4 className="text-sm font-medium mb-1">Racional de Severidad</h4>
          <p className="text-sm text-muted-foreground">{data.severityRationale}</p>
          {data.severityChangeConditions && (
            <p className="text-xs text-muted-foreground mt-2 italic">
              Cambiaría si: {data.severityChangeConditions}
            </p>
          )}
        </div>
      )}

      {/* Root Cause */}
      {data.rootCauseSummary && (
        <div className="rounded-lg border p-4">
          <h4 className="text-sm font-medium mb-1">Causa Raíz</h4>
          <p className="text-sm text-muted-foreground">{data.rootCauseSummary}</p>
        </div>
      )}

      {/* Counterevidence & Gaps */}
      {(data.counterevidence || data.proofGaps) && (
        <div className="rounded-lg border border-yellow-200 dark:border-yellow-800 p-4 bg-yellow-50/50 dark:bg-yellow-950/20">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="h-4 w-4 text-yellow-600" />
            <h4 className="text-sm font-medium">Incertidumbre</h4>
          </div>
          {data.counterevidence && data.counterevidence !== "none identified" && (
            <p className="text-sm text-muted-foreground mb-1">
              <strong>Contraevidencia:</strong> {data.counterevidence}
            </p>
          )}
          {data.proofGaps && data.proofGaps !== "none" && (
            <p className="text-sm text-muted-foreground">
              <strong>Vacíos de prueba:</strong> {data.proofGaps}
            </p>
          )}
        </div>
      )}

      {/* Validation Method */}
      {data.validationMethod && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline">{data.validationMethod.replace(/_/g, " ")}</Badge>
          {data.validationConfidence != null && (
            <span>Confianza calibrada: {Math.round(data.validationConfidence * 100)}%</span>
          )}
        </div>
      )}
    </div>
  );
}

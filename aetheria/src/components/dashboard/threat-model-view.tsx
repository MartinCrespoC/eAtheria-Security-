"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Shield, Users, Lock, AlertTriangle, ChevronDown, ChevronUp } from "lucide-react";

interface ThreatModelActor {
  name: string;
  description: string;
  capabilities: string[];
}

interface ThreatModelBoundary {
  name: string;
  description: string;
  trustLevel: string;
}

interface ThreatModelAsset {
  name: string;
  sensitivity: string;
  location: string;
}

interface ThreatModelThreat {
  id: string;
  description: string;
  actor: string;
  asset: string;
  likelihood: string;
  impact: string;
}

interface ThreatModelData {
  content: string;
  actors: ThreatModelActor[];
  boundaries: ThreatModelBoundary[];
  assets: ThreatModelAsset[];
  threats: ThreatModelThreat[];
  createdAt: string;
}

const TRUST_COLORS: Record<string, string> = {
  high: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  low: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  untrusted: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
};

const LIKELIHOOD_COLORS: Record<string, string> = {
  high: "bg-red-100 text-red-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-green-100 text-green-800",
};

export function ThreatModelView({ data }: { data: ThreatModelData | null }) {
  const [expandedSection, setExpandedSection] = useState<string | null>("threats");

  if (!data) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground">
        <Shield className="mx-auto h-10 w-10 mb-3 opacity-50" />
        <p>No se generó modelo de amenazas para este análisis</p>
        <p className="text-sm mt-1">Disponible en escaneos LIGHTWEIGHT y DEEP</p>
      </div>
    );
  }

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="space-y-4">
      {/* Actors */}
      <SectionCard
        title="Actores"
        icon={<Users className="h-4 w-4" />}
        count={data.actors?.length || 0}
        expanded={expandedSection === "actors"}
        onToggle={() => toggleSection("actors")}
      >
        <div className="grid gap-3 md:grid-cols-2">
          {data.actors?.map((actor, i) => (
            <div key={i} className="rounded-md border p-3">
              <p className="font-medium text-sm">{actor.name}</p>
              <p className="text-xs text-muted-foreground mt-1">{actor.description}</p>
              {actor.capabilities?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {actor.capabilities.map((cap, j) => (
                    <Badge key={j} variant="outline" className="text-xs">{cap}</Badge>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Trust Boundaries */}
      <SectionCard
        title="Límites de Confianza"
        icon={<Lock className="h-4 w-4" />}
        count={data.boundaries?.length || 0}
        expanded={expandedSection === "boundaries"}
        onToggle={() => toggleSection("boundaries")}
      >
        <div className="space-y-2">
          {data.boundaries?.map((boundary, i) => (
            <div key={i} className="flex items-center justify-between rounded-md border p-3">
              <div>
                <p className="font-medium text-sm">{boundary.name}</p>
                <p className="text-xs text-muted-foreground">{boundary.description}</p>
              </div>
              <span className={cn("px-2 py-0.5 rounded text-xs font-medium", TRUST_COLORS[boundary.trustLevel?.toLowerCase()] || TRUST_COLORS.medium)}>
                {boundary.trustLevel}
              </span>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Assets */}
      <SectionCard
        title="Activos"
        icon={<Shield className="h-4 w-4" />}
        count={data.assets?.length || 0}
        expanded={expandedSection === "assets"}
        onToggle={() => toggleSection("assets")}
      >
        <div className="grid gap-2 md:grid-cols-3">
          {data.assets?.map((asset, i) => (
            <div key={i} className="rounded-md border p-3">
              <p className="font-medium text-sm">{asset.name}</p>
              <p className="text-xs text-muted-foreground mt-1">{asset.location}</p>
              <Badge variant="outline" className="mt-2 text-xs">
                Sensibilidad: {asset.sensitivity}
              </Badge>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Threats */}
      <SectionCard
        title="Amenazas"
        icon={<AlertTriangle className="h-4 w-4" />}
        count={data.threats?.length || 0}
        expanded={expandedSection === "threats"}
        onToggle={() => toggleSection("threats")}
      >
        <div className="space-y-2">
          {data.threats?.map((threat, i) => (
            <div key={i} className="rounded-md border p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1">
                  <p className="text-sm font-medium">{threat.id}: {threat.description}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Actor: {threat.actor} → Activo: {threat.asset}
                  </p>
                </div>
                <div className="flex gap-1">
                  <span className={cn("px-1.5 py-0.5 rounded text-xs", LIKELIHOOD_COLORS[threat.likelihood?.toLowerCase()] || "bg-gray-100")}>
                    L: {threat.likelihood}
                  </span>
                  <span className={cn("px-1.5 py-0.5 rounded text-xs", LIKELIHOOD_COLORS[threat.impact?.toLowerCase()] || "bg-gray-100")}>
                    I: {threat.impact}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}

function SectionCard({
  title,
  icon,
  count,
  expanded,
  onToggle,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  count: number;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border">
      <button
        onClick={onToggle}
        className="flex w-full items-center justify-between p-4 text-left hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          {icon}
          <span className="font-medium">{title}</span>
          <Badge variant="secondary" className="text-xs">{count}</Badge>
        </div>
        {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </button>
      {expanded && <div className="border-t p-4">{children}</div>}
    </div>
  );
}

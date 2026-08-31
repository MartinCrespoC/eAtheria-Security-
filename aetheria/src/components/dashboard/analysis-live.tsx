"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Radio } from "lucide-react";
import { ScanProgress } from "@/components/dashboard/scan-progress";

interface AnalysisLiveProps {
  analysisId: string;
  appName: string;
  appId: string;
  version: string;
}

export function AnalysisLive({ analysisId, appName, appId, version }: AnalysisLiveProps) {
  const router = useRouter();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href={`/dashboard/applications/${appId}`}>
          <Button variant="ghost" size="sm">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-text-primary">Análisis en Curso — {appName}</h1>
            <Badge variant="info" className="animate-pulse">
              <Radio className="h-3 w-3 mr-1" /> EN VIVO
            </Badge>
          </div>
          <p className="text-text-secondary mt-1">Versión {version} · Monitoreo en tiempo real</p>
        </div>
      </div>

      {/* Real-time scan progress */}
      <ScanProgress
        analysisId={analysisId}
        onComplete={() => router.refresh()}
      />
    </div>
  );
}

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import {
  StandardsDashboard,
  type BenchmarkRunDTO,
} from "@/components/dashboard/standards-dashboard";

export const dynamic = "force-dynamic";

export default async function StandardsPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  // Benchmark runs are global (system-level proof of detection accuracy and
  // security posture), not scoped to a company. Latest first so the dashboard
  // can pick `runs[0]` per source as the headline.
  const runs = await prisma.benchmarkRun.findMany({
    orderBy: { createdAt: "desc" },
    take: 300,
  });

  const dto: BenchmarkRunDTO[] = runs.map((r) => ({
    id: r.id,
    name: r.name,
    source: r.source,
    kind: r.kind,
    totalCases: r.totalCases,
    tpr: r.tpr ?? 0,
    fpr: r.fpr ?? 0,
    precision: r.precision ?? 0,
    recall: r.recall ?? 0,
    score: r.score ?? 0,
    byCategory: (r.byCategory as Record<string, unknown> | null) ?? null,
    metrics: (r.metrics as Record<string, unknown> | null) ?? null,
    createdAt: r.createdAt.toISOString(),
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Estándares de la Industria</h1>
        <p className="text-text-secondary mt-1">
          Precisión de detección (OWASP, CVE, WSTG) y postura de seguridad
          (Scorecard, Best Practices Badge) medidas frente a estándares abiertos.
        </p>
      </div>
      <StandardsDashboard runs={dto} />
    </div>
  );
}

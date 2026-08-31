import { prisma } from "@/lib/db";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Scan, Cpu, DollarSign, TrendingUp, Building2, Settings2 } from "lucide-react";
import { TokenPricingConfig } from "@/components/admin/token-pricing-config";

export default async function AdminTokensPage() {
  // eslint-disable-next-line react-hooks/purity
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const [tokenUsage, analyses, companies, globalAgg] = await Promise.all([
    prisma.tokenUsage.findMany({
      where: { date: { gte: thirtyDaysAgo } },
      include: {
        model: { select: { name: true, modelId: true, inputTokenCost: true, outputTokenCost: true } },
        company: { select: { name: true } },
      },
      orderBy: { date: "desc" },
      take: 50,
    }),
    prisma.analysis.findMany({
      where: { status: "COMPLETED", inputTokens: { gt: 0 } },
      include: {
        appVersion: {
          include: { application: { select: { name: true, company: { select: { name: true } } } } },
        },
      },
      orderBy: { completedAt: "desc" },
      take: 30,
    }),
    prisma.company.findMany({
      where: { isActive: true },
      select: {
        id: true,
        name: true,
        slug: true,
        customInputTokenCost: true,
        customOutputTokenCost: true,
        aiTokenLimit: true,
        aiCostLimit: true,
      },
      orderBy: { name: "asc" },
    }),
    prisma.tokenUsage.aggregate({
      where: { date: { gte: thirtyDaysAgo } },
      _sum: { inputTokens: true, outputTokens: true, totalCost: true },
    }),
  ]);

  const totalInput = Number(globalAgg._sum.inputTokens || 0);
  const totalOutput = Number(globalAgg._sum.outputTokens || 0);
  const totalCost = Number(globalAgg._sum.totalCost || 0);
  const dailyAvg = totalCost / 30;
  const monthlyProjection = dailyAvg * 30;

  // Per-scan stats
  const scanTotalIn = analyses.reduce((sum, a) => sum + Number(a.inputTokens), 0);
  const scanTotalOut = analyses.reduce((sum, a) => sum + Number(a.outputTokens), 0);
  const scanTotalCost = analyses.reduce((sum, a) => sum + (a.estimatedCost ? Number(a.estimatedCost) : 0), 0);
  const avgCostPerScan = analyses.length > 0 ? scanTotalCost / analyses.length : 0;

  // Per-company aggregation from token usage
  const companyCostMap = new Map<string, { name: string; input: number; output: number; cost: number }>();
  for (const t of tokenUsage) {
    const key = t.company?.name || "Sistema";
    const existing = companyCostMap.get(key) || { name: key, input: 0, output: 0, cost: 0 };
    existing.input += Number(t.inputTokens);
    existing.output += Number(t.outputTokens);
    existing.cost += Number(t.totalCost);
    companyCostMap.set(key, existing);
  }
  const companyCosts = [...companyCostMap.values()].sort((a, b) => b.cost - a.cost);

  // Serialize companies for client component
  const serializedCompanies = companies.map((c) => ({
    id: c.id,
    name: c.name,
    slug: c.slug,
    customInputTokenCost: c.customInputTokenCost ? Number(c.customInputTokenCost) : null,
    customOutputTokenCost: c.customOutputTokenCost ? Number(c.customOutputTokenCost) : null,
    aiTokenLimit: c.aiTokenLimit ?? null,
    aiCostLimit: c.aiCostLimit ? Number(c.aiCostLimit) : null,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Administración de Tokens & Costos IA</h1>
        <p className="text-text-secondary mt-1">
          Visión global del consumo, costos y pricing por empresa — Solo admin principal
        </p>
      </div>

      {/* Global summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <p className="text-sm text-text-secondary">Tokens Entrada (30d)</p>
            <p className="mt-1 text-2xl font-bold text-text-primary">{totalInput.toLocaleString()}</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <p className="text-sm text-text-secondary">Tokens Salida (30d)</p>
            <p className="mt-1 text-2xl font-bold text-text-primary">{totalOutput.toLocaleString()}</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <p className="text-sm text-text-secondary">Costo Total (30d)</p>
            <p className="mt-1 text-2xl font-bold text-emerald-400">${totalCost.toFixed(4)}</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-1">
              <TrendingUp className="h-3.5 w-3.5 text-amber-400" />
              <p className="text-sm text-text-secondary">Proyección Mensual</p>
            </div>
            <p className="mt-1 text-2xl font-bold text-amber-400">${monthlyProjection.toFixed(4)}</p>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <p className="text-sm text-text-secondary">Costo Promedio/Scan</p>
            <p className="mt-1 text-2xl font-bold text-accent">${avgCostPerScan.toFixed(5)}</p>
            <p className="text-xs text-text-muted mt-1">{analyses.length} scans con IA</p>
          </CardContent>
        </Card>
      </div>

      {/* Per-company cost breakdown */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Building2 className="h-4 w-4 text-accent" />
            Costo por Empresa (30 días)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {companyCosts.length === 0 ? (
            <p className="text-text-muted text-center py-8">Sin consumo registrado</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Empresa</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Tokens In</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Tokens Out</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Total Tokens</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Costo</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">% del Total</th>
                  </tr>
                </thead>
                <tbody>
                  {companyCosts.map((c) => (
                    <tr key={c.name} className="border-b border-border hover:bg-surface">
                      <td className="px-4 py-3 text-sm text-text-primary font-medium">{c.name}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary">{c.input.toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary">{c.output.toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary">{(c.input + c.output).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-right text-emerald-400 font-medium">${c.cost.toFixed(4)}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-secondary">
                        {totalCost > 0 ? ((c.cost / totalCost) * 100).toFixed(1) : 0}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Per-scan cost table */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Scan className="h-4 w-4 text-accent" />
            Costo por Análisis (Scans)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {analyses.length === 0 ? (
            <p className="text-text-muted text-center py-8">Sin análisis con consumo de tokens</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Aplicación</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Empresa</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Nivel</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Tokens In</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Tokens Out</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Costo</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Duración</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Fecha</th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.map((a) => {
                    const inT = Number(a.inputTokens);
                    const outT = Number(a.outputTokens);
                    const cost = a.estimatedCost ? Number(a.estimatedCost) : 0;
                    return (
                      <tr key={a.id} className="border-b border-border hover:bg-surface">
                        <td className="px-4 py-3 text-sm text-text-primary">{a.appVersion.application.name}</td>
                        <td className="px-4 py-3 text-sm text-text-secondary">{a.appVersion.application.company.name}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            a.scanLevel === "DEEP" ? "bg-red-500/10 text-red-400" :
                            a.scanLevel === "LIGHTWEIGHT" ? "bg-amber-500/10 text-amber-400" :
                            "bg-slate-500/10 text-text-secondary"
                          }`}>
                            {a.scanLevel}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-right text-text-primary">{inT.toLocaleString()}</td>
                        <td className="px-4 py-3 text-sm text-right text-text-primary">{outT.toLocaleString()}</td>
                        <td className="px-4 py-3 text-sm text-right text-emerald-400 font-medium">${cost.toFixed(5)}</td>
                        <td className="px-4 py-3 text-sm text-right text-text-secondary">{a.duration ?? "-"}s</td>
                        <td className="px-4 py-3 text-xs text-right text-text-muted">
                          {a.completedAt ? new Date(a.completedAt).toLocaleString("es-ES") : "-"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Token pricing configuration per company */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-amber-400" />
            Configuración de Pricing por Empresa
          </CardTitle>
        </CardHeader>
        <CardContent>
          <TokenPricingConfig companies={serializedCompanies} />
        </CardContent>
      </Card>

      {/* Token usage by model */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Cpu className="h-4 w-4 text-purple-400" />
            Consumo por Modelo (30 días)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {tokenUsage.length === 0 ? (
            <p className="text-text-muted text-center py-8">Sin registros de consumo por modelo</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Empresa</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Modelo</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Input</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Output</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Costo</th>
                    <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Fecha</th>
                  </tr>
                </thead>
                <tbody>
                  {tokenUsage.map((t) => (
                    <tr key={t.id} className="border-b border-border">
                      <td className="px-4 py-3 text-sm text-text-primary">{t.company?.name || "Sistema"}</td>
                      <td className="px-4 py-3 text-sm text-purple-400">{t.model.name}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary">{Number(t.inputTokens).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary">{Number(t.outputTokens).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-right text-text-primary font-medium">${Number(t.totalCost).toFixed(4)}</td>
                      <td className="px-4 py-3 text-xs text-right text-text-muted">{new Date(t.date).toLocaleDateString("es-ES")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

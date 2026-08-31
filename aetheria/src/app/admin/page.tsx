import { prisma } from "@/lib/db";
import { Card, CardContent } from "@/components/ui/card";
import { Users, AppWindow, Scan, Brain, Shield, AlertTriangle } from "lucide-react";

export default async function AdminDashboard() {
  const [
    userCount,
    appCount,
    analysisCount,
    vulnCount,
    aiModelCount,
    criticalVulns,
  ] = await Promise.all([
    prisma.user.count(),
    prisma.application.count(),
    prisma.analysis.count(),
    prisma.vulnerability.count(),
    prisma.aIModel.count({ where: { isActive: true } }),
    prisma.vulnerability.count({ where: { severity: "CRITICAL" } }),
  ]);

  const stats = [
    { label: "Usuarios", value: userCount, icon: Users, color: "from-purple-500 to-pink-500" },
    { label: "Aplicaciones", value: appCount, icon: AppWindow, color: "from-emerald-500 to-teal-500" },
    { label: "Análisis", value: analysisCount, icon: Scan, color: "from-amber-500 to-orange-500" },
    { label: "Vulnerabilidades", value: vulnCount, icon: AlertTriangle, color: "from-red-500 to-rose-500" },
    { label: "Críticas", value: criticalVulns, icon: Shield, color: "from-red-600 to-red-400" },
    { label: "Modelos IA", value: aiModelCount, icon: Brain, color: "from-violet-500 to-purple-500" },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-text-primary">Panel de Administración</h1>
        <p className="text-text-secondary mt-1">
          Vista de tu instancia AETHERIA (uso personal)
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {stats.map((stat) => (
          <Card key={stat.label} className="border-border bg-card">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-text-secondary">{stat.label}</p>
                  <p className="mt-2 text-3xl font-bold text-text-primary">
                    {stat.value.toLocaleString()}
                  </p>
                </div>
                <div className={`h-12 w-12 rounded-xl bg-gradient-to-br ${stat.color} flex items-center justify-center`}>
                  <stat.icon className="h-6 w-6 text-text-primary" />
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

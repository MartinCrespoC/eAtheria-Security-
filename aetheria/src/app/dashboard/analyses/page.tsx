import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { AnalysesList } from "@/components/dashboard/analyses-list";

export default async function AnalysesPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;
  const analyses = await prisma.analysis.findMany({
    where: companyId
      ? { appVersion: { application: { companyId } } }
      : undefined,
    include: {
      appVersion: {
        include: { application: { select: { id: true, name: true } } },
      },
    },
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Análisis de Seguridad</h1>
        <p className="text-text-secondary mt-1">
          Historial de todos los análisis ejecutados
        </p>
      </div>
      <AnalysesList analyses={analyses} />
    </div>
  );
}

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { ApplicationsList } from "@/components/dashboard/applications-list";

export default async function ApplicationsPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;

  const applications = await prisma.application.findMany({
    where: companyId ? { companyId } : undefined,
    include: {
      versions: {
        orderBy: { createdAt: "desc" },
        take: 1,
        include: {
          analyses: {
            orderBy: { createdAt: "desc" },
            take: 1,
            select: { status: true, criticalCount: true, highCount: true, totalIssues: true, createdAt: true },
          },
        },
      },
      _count: { select: { versions: true } },
    },
    orderBy: { updatedAt: "desc" },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Aplicaciones</h1>
          <p className="text-text-secondary mt-1">
            Gestiona las aplicaciones de tu organización
          </p>
        </div>
      </div>

      <ApplicationsList applications={applications} />
    </div>
  );
}

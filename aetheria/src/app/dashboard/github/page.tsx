import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { GitHubConnections } from "@/components/dashboard/github-connections";

export default async function GitHubPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;
  const connections = companyId
    ? await prisma.githubConnection.findMany({
        where: { companyId },
        orderBy: { createdAt: "desc" },
      })
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Integración GitHub</h1>
        <p className="text-text-secondary mt-1">
          Conecta repositorios de GitHub para análisis automáticos
        </p>
      </div>
      <GitHubConnections connections={connections} />
    </div>
  );
}

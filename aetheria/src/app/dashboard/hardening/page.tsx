import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { HardeningPortfolio } from "@/components/dashboard/hardening-portfolio";

export default async function HardeningPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;

  // Get recent analyses with hardening proposals
  const proposals = companyId
    ? await prisma.hardeningProposal.findMany({
        where: { companyId },
        orderBy: { createdAt: "desc" },
        take: 50,
      })
    : [];

  const serialized = JSON.parse(JSON.stringify(proposals));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Hardening de Seguridad</h1>
        <p className="text-text-secondary mt-1">
          Propuestas estructurales de mejora basadas en hallazgos de escaneo
        </p>
      </div>
      <HardeningPortfolio initialProposals={serialized} />
    </div>
  );
}

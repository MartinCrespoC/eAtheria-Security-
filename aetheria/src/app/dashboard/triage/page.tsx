import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { TriagePanel } from "@/components/dashboard/triage-panel";

export default async function TriagePage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;

  const triageResults = companyId
    ? await prisma.triageResult.findMany({
        where: { companyId },
        orderBy: { createdAt: "desc" },
        take: 100,
      })
    : [];

  const serialized = JSON.parse(JSON.stringify(triageResults));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Triaje de Findings</h1>
        <p className="text-text-secondary mt-1">
          Importa y clasifica findings externos (SARIF, CVE, GHSA, Bug Bounty)
        </p>
      </div>
      <TriagePanel initialResults={serialized} />
    </div>
  );
}

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { VulnerabilitiesList } from "@/components/dashboard/vulnerabilities-list";

export default async function VulnerabilitiesPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;
  const vulnerabilities = await prisma.vulnerability.findMany({
    where: companyId
      ? { analysis: { appVersion: { application: { companyId } } } }
      : undefined,
    select: {
      id: true,
      severity: true,
      confidence: true,
      category: true,
      title: true,
      description: true,
      filePath: true,
      lineStart: true,
      lineEnd: true,
      codeSnippet: true,
      cweId: true,
      cveId: true,
      owaspTop10: true,
      aiValidated: true,
      isFalsePositive: true,
      smartFix: true,
      fixExplanation: true,
      status: true,
      createdAt: true,
      analysis: {
        select: {
          appVersion: {
            select: {
              version: true,
              application: { select: { name: true } },
            },
          },
        },
      },
    },
    orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
    take: 100,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Vulnerabilidades</h1>
        <p className="text-text-secondary mt-1">
          Todas las vulnerabilidades detectadas en tu organización
        </p>
      </div>
      <VulnerabilitiesList vulnerabilities={vulnerabilities} />
    </div>
  );
}

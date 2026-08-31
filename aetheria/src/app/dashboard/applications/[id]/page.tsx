import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect, notFound } from "next/navigation";
import { ApplicationDetail } from "@/components/dashboard/application-detail";

export default async function ApplicationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await auth();
  if (!session?.user?.companyId) redirect("/login");

  const { id } = await params;

  const application = await prisma.application.findFirst({
    where: { id, companyId: session.user.companyId },
    include: {
      company: { select: { defaultScanLevel: true } },
      versions: {
        include: {
          analyses: {
            select: {
              id: true,
              status: true,
              totalIssues: true,
              criticalCount: true,
              highCount: true,
              mediumCount: true,
              lowCount: true,
              createdAt: true,
              completedAt: true,
            },
            orderBy: { createdAt: "desc" },
            take: 5,
          },
        },
        orderBy: { createdAt: "desc" },
      },
    },
  });

  if (!application) notFound();

  return (
    <div className="space-y-6">
      <ApplicationDetail application={application} defaultScanLevel={application.company.defaultScanLevel} />
    </div>
  );
}

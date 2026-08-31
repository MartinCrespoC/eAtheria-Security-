import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { DashboardStats } from "@/components/dashboard/dashboard-stats";
import { RecentAnalyses } from "@/components/dashboard/recent-analyses";
import { VulnerabilityChart } from "@/components/dashboard/vulnerability-chart";
import { SecurityScoreRing } from "@/components/dashboard/security-score-ring";
import { QuickActions } from "@/components/dashboard/quick-actions";
import { WelcomeBanner } from "@/components/dashboard/welcome-banner";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;

  const [appCount, analysisCount, vulnCount, recentAnalyses, vulnsBySeverity] =
    await Promise.all([
      prisma.application.count({
        where: companyId ? { companyId } : undefined,
      }),
      prisma.analysis.count({
        where: companyId
          ? { appVersion: { application: { companyId } } }
          : undefined,
      }),
      prisma.vulnerability.count({
        where: companyId
          ? { analysis: { appVersion: { application: { companyId } } } }
          : undefined,
      }),
      prisma.analysis.findMany({
        where: companyId
          ? { appVersion: { application: { companyId } } }
          : undefined,
        select: {
          id: true,
          status: true,
          totalIssues: true,
          criticalCount: true,
          highCount: true,
          createdAt: true,
          appVersion: {
            select: {
              version: true,
              application: { select: { name: true } },
            },
          },
        },
        orderBy: { createdAt: "desc" },
        take: 5,
      }),
      prisma.vulnerability.groupBy({
        by: ["severity"],
        _count: true,
        where: companyId
          ? { analysis: { appVersion: { application: { companyId } } } }
          : undefined,
      }),
    ]);

  const criticalCount = vulnsBySeverity.find(
    (v) => v.severity === "CRITICAL"
  )?._count ?? 0;
  const highCount = vulnsBySeverity.find(
    (v) => v.severity === "HIGH"
  )?._count ?? 0;

  const stats = {
    applications: appCount,
    analyses: analysisCount,
    vulnerabilities: vulnCount,
    criticalVulns: criticalCount,
  };

  const severityData = vulnsBySeverity.map((v) => ({
    severity: v.severity,
    count: v._count,
  }));

  // Security score: 100 base, minus weighted severity counts
  const rawScore = Math.max(
    0,
    100 - criticalCount * 15 - highCount * 5 - (vulnCount - criticalCount - highCount) * 1
  );
  const securityScore = analysisCount === 0 ? null : Math.min(100, rawScore);

  return (
    <div className="space-y-8">
      <WelcomeBanner firstName={session.user.firstName} />

      <DashboardStats stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <SecurityScoreRing score={securityScore} />
        </div>
        <div className="lg:col-span-2">
          <QuickActions />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VulnerabilityChart data={severityData} />
        <RecentAnalyses analyses={recentAnalyses} />
      </div>
    </div>
  );
}

import { prisma } from "@/lib/db";
import { AnalyticsDashboard } from "@/components/admin/analytics-dashboard";

export default async function AnalyticsPage() {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const [totalEvents, eventsByType, topPages] = await Promise.all([
    prisma.analyticsEvent.count({
      where: { createdAt: { gte: thirtyDaysAgo } },
    }),
    prisma.analyticsEvent.groupBy({
      by: ["eventType"],
      where: { createdAt: { gte: thirtyDaysAgo } },
      _count: true,
      orderBy: { _count: { eventType: "desc" } },
      take: 10,
    }),
    prisma.analyticsEvent.groupBy({
      by: ["pageUrl"],
      where: { createdAt: { gte: thirtyDaysAgo }, pageUrl: { not: null } },
      _count: true,
      orderBy: { _count: { pageUrl: "desc" } },
      take: 10,
    }),
  ]);

  const data = {
    totalEvents,
    eventsByType: eventsByType.map((e) => ({ type: e.eventType, count: e._count })),
    topPages: topPages.map((p) => ({ url: p.pageUrl || "", count: p._count })),
  };

  return <AnalyticsDashboard data={data} />;
}

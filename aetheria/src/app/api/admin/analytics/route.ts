import { NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function GET() {
  try {
    await requireSystemAdmin();

    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalEvents,
      last7DaysEvents,
      eventsByType,
      topPages,
      topBrowsers,
      topCountries,
      dailyEvents,
    ] = await Promise.all([
      prisma.analyticsEvent.count({
        where: { createdAt: { gte: thirtyDaysAgo } },
      }),
      prisma.analyticsEvent.count({
        where: { createdAt: { gte: sevenDaysAgo } },
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
      prisma.analyticsEvent.groupBy({
        by: ["browser"],
        where: { createdAt: { gte: thirtyDaysAgo }, browser: { not: null } },
        _count: true,
        orderBy: { _count: { browser: "desc" } },
        take: 5,
      }),
      prisma.analyticsEvent.groupBy({
        by: ["country"],
        where: { createdAt: { gte: thirtyDaysAgo }, country: { not: null } },
        _count: true,
        orderBy: { _count: { country: "desc" } },
        take: 10,
      }),
      // Daily event counts (last 30 days)
      prisma.$queryRaw`
        SELECT DATE("createdAt") as date, COUNT(*)::int as count
        FROM "analytics_events"
        WHERE "createdAt" >= ${thirtyDaysAgo}
        GROUP BY DATE("createdAt")
        ORDER BY date ASC
      ` as Promise<{ date: Date; count: number }[]>,
    ]);

    return NextResponse.json({
      totalEvents,
      last7DaysEvents,
      eventsByType: eventsByType.map((e) => ({ type: e.eventType, count: e._count })),
      topPages: topPages.map((p) => ({ url: p.pageUrl, count: p._count })),
      topBrowsers: topBrowsers.map((b) => ({ browser: b.browser, count: b._count })),
      topCountries: topCountries.map((c) => ({ country: c.country, count: c._count })),
      dailyEvents,
    });
  } catch (error) {
    console.error("Analytics error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

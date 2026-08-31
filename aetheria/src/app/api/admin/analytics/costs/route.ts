import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * GET /api/admin/analytics/costs
 * Aggregated AI cost data for global admin:
 * - Total cost across all companies
 * - Per-company breakdown
 * - Per-model breakdown
 * - Daily trend (last 30 days)
 * - Monthly projection
 */
export async function GET(request: NextRequest) {
  try {
    await requireSystemAdmin();

    const { searchParams } = new URL(request.url);
    const days = parseInt(searchParams.get("days") || "30", 10);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [tokenUsage, perCompany, perModel, dailyTrend, scanCosts] = await Promise.all([
      // Global totals
      prisma.tokenUsage.aggregate({
        where: { date: { gte: since } },
        _sum: { inputTokens: true, outputTokens: true, totalCost: true },
      }),
      // Per-company aggregation
      prisma.tokenUsage.groupBy({
        by: ["companyId"],
        where: { date: { gte: since } },
        _sum: { inputTokens: true, outputTokens: true, totalCost: true },
      }),
      // Per-model aggregation
      prisma.tokenUsage.groupBy({
        by: ["modelId"],
        where: { date: { gte: since } },
        _sum: { inputTokens: true, outputTokens: true, totalCost: true },
      }),
      // Daily trend
      prisma.$queryRaw`
        SELECT DATE("date") as date,
               SUM("inputTokens")::bigint as "inputTokens",
               SUM("outputTokens")::bigint as "outputTokens",
               SUM("totalCost")::numeric as "totalCost"
        FROM "token_usage"
        WHERE "date" >= ${since}
        GROUP BY DATE("date")
        ORDER BY date ASC
      ` as Promise<{ date: Date; inputTokens: bigint; outputTokens: bigint; totalCost: number }[]>,
      // Per-scan costs (last 50 completed analyses with token data)
      prisma.analysis.findMany({
        where: { status: "COMPLETED", inputTokens: { gt: 0 } },
        select: {
          id: true,
          estimatedCost: true,
          inputTokens: true,
          outputTokens: true,
          duration: true,
          scanLevel: true,
          createdAt: true,
          appVersion: {
            select: {
              version: true,
              application: { select: { name: true, company: { select: { name: true, id: true } } } },
            },
          },
        },
        orderBy: { completedAt: "desc" },
        take: 50,
      }),
    ]);

    // Resolve company names for per-company breakdown
    const companyIds = perCompany.map((c) => c.companyId).filter(Boolean) as string[];
    const companies = companyIds.length > 0
      ? await prisma.company.findMany({
          where: { id: { in: companyIds } },
          select: { id: true, name: true, slug: true, customInputTokenCost: true, customOutputTokenCost: true, aiTokenLimit: true, aiCostLimit: true },
        })
      : [];
    const companyMap = new Map(companies.map((c) => [c.id, c]));

    // Resolve model names
    const modelIds = perModel.map((m) => m.modelId);
    const models = modelIds.length > 0
      ? await prisma.aIModel.findMany({
          where: { id: { in: modelIds } },
          select: { id: true, name: true, modelId: true, inputTokenCost: true, outputTokenCost: true },
        })
      : [];
    const modelMap = new Map(models.map((m) => [m.id, m]));

    // Monthly projection based on daily average
    const totalCost = Number(tokenUsage._sum.totalCost || 0);
    const dailyAvg = totalCost / Math.max(days, 1);
    const monthlyProjection = dailyAvg * 30;

    return NextResponse.json({
      period: { days, since: since.toISOString() },
      totals: {
        inputTokens: Number(tokenUsage._sum.inputTokens || 0),
        outputTokens: Number(tokenUsage._sum.outputTokens || 0),
        totalCost,
        dailyAverage: dailyAvg,
        monthlyProjection,
      },
      perCompany: perCompany.map((c) => {
        const company = c.companyId ? companyMap.get(c.companyId) : null;
        return {
          companyId: c.companyId,
          companyName: company?.name || "Sistema",
          companySlug: company?.slug || "system",
          inputTokens: Number(c._sum.inputTokens || 0),
          outputTokens: Number(c._sum.outputTokens || 0),
          totalCost: Number(c._sum.totalCost || 0),
          customInputTokenCost: company?.customInputTokenCost ? Number(company.customInputTokenCost) : null,
          customOutputTokenCost: company?.customOutputTokenCost ? Number(company.customOutputTokenCost) : null,
          aiTokenLimit: company?.aiTokenLimit ?? null,
          aiCostLimit: company?.aiCostLimit ? Number(company.aiCostLimit) : null,
        };
      }),
      perModel: perModel.map((m) => {
        const model = modelMap.get(m.modelId);
        return {
          modelId: m.modelId,
          modelName: model?.name || "Unknown",
          modelIdentifier: model?.modelId || "",
          inputTokenCost: model ? Number(model.inputTokenCost) : null,
          outputTokenCost: model ? Number(model.outputTokenCost) : null,
          inputTokens: Number(m._sum.inputTokens || 0),
          outputTokens: Number(m._sum.outputTokens || 0),
          totalCost: Number(m._sum.totalCost || 0),
        };
      }),
      dailyTrend: dailyTrend.map((d) => ({
        date: d.date instanceof Date ? d.date.toISOString().split("T")[0] : String(d.date),
        inputTokens: Number(d.inputTokens),
        outputTokens: Number(d.outputTokens),
        totalCost: Number(d.totalCost),
      })),
      scanCosts: scanCosts.map((s) => ({
        id: s.id,
        appName: s.appVersion.application.name,
        companyName: s.appVersion.application.company.name,
        companyId: s.appVersion.application.company.id,
        version: s.appVersion.version,
        scanLevel: s.scanLevel,
        inputTokens: Number(s.inputTokens),
        outputTokens: Number(s.outputTokens),
        estimatedCost: s.estimatedCost ? Number(s.estimatedCost) : null,
        duration: s.duration,
        createdAt: s.createdAt.toISOString(),
      })),
    });
  } catch (error) {
    console.error("Admin costs analytics error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PUT /api/admin/analytics/costs
 * Update per-company custom token pricing
 * Body: { companyId, customInputTokenCost?, customOutputTokenCost? }
 */
export async function PUT(request: NextRequest) {
  try {
    await requireSystemAdmin();

    const body = await request.json();
    const { companyId, customInputTokenCost, customOutputTokenCost } = body;

    if (!companyId) {
      return NextResponse.json({ error: "companyId is required" }, { status: 400 });
    }

    const company = await prisma.company.findUnique({ where: { id: companyId } });
    if (!company) {
      return NextResponse.json({ error: "Company not found" }, { status: 404 });
    }

    const updated = await prisma.company.update({
      where: { id: companyId },
      data: {
        ...(customInputTokenCost !== undefined && { customInputTokenCost }),
        ...(customOutputTokenCost !== undefined && { customOutputTokenCost }),
      },
      select: { id: true, name: true, customInputTokenCost: true, customOutputTokenCost: true },
    });

    return NextResponse.json({
      success: true,
      company: {
        id: updated.id,
        name: updated.name,
        customInputTokenCost: updated.customInputTokenCost ? Number(updated.customInputTokenCost) : null,
        customOutputTokenCost: updated.customOutputTokenCost ? Number(updated.customOutputTokenCost) : null,
      },
    });
  } catch (error) {
    console.error("Admin costs update error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

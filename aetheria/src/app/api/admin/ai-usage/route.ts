import { NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { checkQuota } from "@/lib/ai/provider-selector";

/**
 * GET /api/admin/ai-usage
 * Returns AI usage statistics for the current month for the workspace.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const ws = await prisma.company.findFirst({
      orderBy: { createdAt: "asc" },
      select: { id: true },
    });
    if (!ws) {
      return NextResponse.json({ error: "Workspace no encontrado" }, { status: 404 });
    }

    const companyId = ws.id;
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    // Get quota status (handles limits + aggregation)
    const quota = await checkQuota(companyId);

    // Get per-model breakdown for this month
    const perModel = await prisma.tokenUsage.findMany({
      where: {
        companyId,
        date: { gte: monthStart },
      },
      select: {
        inputTokens: true,
        outputTokens: true,
        totalCost: true,
        modelId: true,
        date: true,
      },
      orderBy: { date: "desc" },
    });

    // Group by model
    const modelMap = new Map<string, { inputTokens: number; outputTokens: number; totalCost: number }>();
    for (const entry of perModel) {
      const existing = modelMap.get(entry.modelId) || { inputTokens: 0, outputTokens: 0, totalCost: 0 };
      existing.inputTokens += Number(entry.inputTokens);
      existing.outputTokens += Number(entry.outputTokens);
      existing.totalCost += Number(entry.totalCost);
      modelMap.set(entry.modelId, existing);
    }

    // Resolve model names
    const modelIds = Array.from(modelMap.keys());
    const models = await prisma.aIModel.findMany({
      where: { id: { in: modelIds } },
      select: { id: true, name: true, modelId: true, aiProvider: { select: { name: true } } },
    });

    const modelBreakdown = models.map((m) => {
      const usage = modelMap.get(m.id)!;
      return {
        modelId: m.id,
        modelName: m.name,
        modelIdStr: m.modelId,
        providerName: m.aiProvider?.name || "Unknown",
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        totalCost: usage.totalCost,
      };
    });

    // Get daily trend (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const dailyUsage = await prisma.tokenUsage.findMany({
      where: {
        companyId,
        date: { gte: thirtyDaysAgo },
      },
      select: {
        date: true,
        inputTokens: true,
        outputTokens: true,
        totalCost: true,
      },
      orderBy: { date: "asc" },
    });

    const dailyTrend = dailyUsage.map((d) => ({
      date: d.date.toISOString().split("T")[0],
      inputTokens: Number(d.inputTokens),
      outputTokens: Number(d.outputTokens),
      totalCost: Number(d.totalCost),
    }));

    return NextResponse.json({
      quota,
      modelBreakdown,
      dailyTrend,
      summary: {
        totalTokens: quota.tokensUsed,
        totalCost: quota.costUsed,
        tokenLimit: quota.tokenLimit,
        costLimit: quota.costLimit,
        percentUsed: quota.percentUsed,
        remaining: quota.remaining,
      },
    });
  } catch (error) {
    console.error("Error fetching company AI usage:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

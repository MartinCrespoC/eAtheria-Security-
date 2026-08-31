import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import {
  checkProviderHealth,
  checkAllProviders,
  getProviderStatus,
  getHealthHistory,
  getProviderUptime,
} from "@/lib/ai/health-monitor";

/**
 * GET /api/admin/ai-configuration/health
 * Returns health status for all providers, plus history for a specific provider if ?providerId=
 */
export async function GET(request: NextRequest) {
  try {
    await requireSystemAdmin();
    const { searchParams } = new URL(request.url);
    const providerId = searchParams.get("providerId");
    const hours = parseInt(searchParams.get("hours") || "24", 10);

    if (providerId) {
      // Return health detail for a specific provider
      const [status, history, uptime] = await Promise.all([
        getProviderStatus(providerId),
        getHealthHistory(providerId, hours),
        getProviderUptime(providerId, hours),
      ]);

      // Also get provider name
      const provider = await prisma.aIProvider.findUnique({
        where: { id: providerId },
        select: { id: true, name: true, slug: true },
      });

      return NextResponse.json({
        provider,
        status,
        uptime,
        history,
      });
    }

    // Return health summary for all providers
    const providers = await prisma.aIProvider.findMany({
      orderBy: [{ isActive: "desc" }, { name: "asc" }],
      select: { id: true, name: true, slug: true, type: true, isActive: true },
    });

    const statuses = await Promise.all(
      providers.map((p) => getProviderStatus(p.id))
    );

    const result = providers.map((p, idx) => ({
      ...p,
      health: statuses[idx],
    }));

    return NextResponse.json(result);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching health status:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * POST /api/admin/ai-configuration/health
 * Trigger a health check. If providerId in body, check that one.
 * Otherwise check all providers.
 */
export async function POST(request: NextRequest) {
  try {
    await requireSystemAdmin();
    const body = await request.json().catch(() => ({}));
    const providerId = body?.providerId;

    if (providerId) {
      const result = await checkProviderHealth(providerId);
      return NextResponse.json(result);
    }

    const summary = await checkAllProviders();
    return NextResponse.json(summary);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error running health check:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

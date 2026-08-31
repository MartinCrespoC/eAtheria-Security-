import { NextRequest, NextResponse } from "next/server";
import { checkAllProviders } from "@/lib/ai/health-monitor";

/**
 * GET /api/cron/ai-health
 * Cron endpoint to run health checks on all AI providers.
 * Secured with CRON_SECRET env var (checked via Authorization header or query param).
 *
 * Can be called by external cron (cron-job.org) or Vercel Cron.
 */
export async function GET(request: NextRequest) {
  try {
    // Verify authorization via CRON_SECRET
    const authHeader = request.headers.get("authorization");
    const { searchParams } = new URL(request.url);
    const secretParam = searchParams.get("secret");
    const cronSecret = process.env.CRON_SECRET;

    // Allow bypass in development if no secret is configured
    const isDev = process.env.NODE_ENV === "development";

    if (cronSecret) {
      const providedToken =
        authHeader?.replace("Bearer ", "") || secretParam || "";
      if (providedToken !== cronSecret) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
      }
    } else if (!isDev) {
      // In production, require a secret
      return NextResponse.json(
        { error: "CRON_SECRET not configured" },
        { status: 500 }
      );
    }

    const summary = await checkAllProviders();

    return NextResponse.json({
      ok: true,
      timestamp: new Date().toISOString(),
      ...summary,
    });
  } catch (error) {
    console.error("[cron/ai-health] Error running health checks:", error);
    return NextResponse.json(
      {
        ok: false,
        error: error instanceof Error ? error.message : "Internal error",
      },
      { status: 500 }
    );
  }
}

/**
 * POST /api/cron/ai-health
 * Same as GET but supports POST for webhook-style cron triggers.
 */
export async function POST(request: NextRequest) {
  return GET(request);
}

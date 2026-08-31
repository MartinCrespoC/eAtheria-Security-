import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

/**
 * Internal API endpoint for middleware to fetch company settings.
 * Only accessible with the internal key (NEXTAUTH_SECRET).
 */
export async function GET(request: NextRequest) {
  const internalKey = request.headers.get("x-internal-key");
  if (internalKey !== (process.env.NEXTAUTH_SECRET || "")) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId");

  if (!companyId) {
    return NextResponse.json({ error: "companyId required" }, { status: 400 });
  }

  const settings = await prisma.companySettings.findUnique({
    where: { companyId },
    select: {
      rateLimitPerMinute: true,
      sessionTimeoutMinutes: true,
      maxLoginAttempts: true,
      requireTwoFactor: true,
    },
  });

  if (!settings) {
    return NextResponse.json({
      rateLimitPerMinute: 60,
      sessionTimeoutMinutes: 480,
      maxLoginAttempts: 5,
      requireTwoFactor: false,
    });
  }

  return NextResponse.json(settings);
}

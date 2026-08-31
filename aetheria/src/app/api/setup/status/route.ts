import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

/**
 * GET /api/setup/status
 *
 * Returns the current setup status:
 * - { configured: false, step: "database" } if DB is not initialized
 * - { configured: true } if setup is complete
 * - { configured: false, step: <current>, ...details } if in progress
 *
 * This route is always accessible (needed to check setup state).
 */
export async function GET() {
  try {
    // Try to query SystemConfig — if this fails, DB is not initialized
    const setupComplete = await prisma.systemConfig.findUnique({
      where: { key: "setup_complete" },
    });

    if (setupComplete?.value === true) {
      return NextResponse.json({ configured: true });
    }

    // Setup not complete — determine current step
    const provider =
      process.env.DATABASE_PROVIDER || "postgresql";

    // Check if admin exists
    const admin = await prisma.user.findFirst({
      where: { isSystemAdmin: true },
      select: { email: true },
    });

    if (!admin) {
      return NextResponse.json({
        configured: false,
        step: "admin",
        provider,
      });
    }

    // Individual mode: the workspace is auto-created with the admin account,
    // so the wizard goes straight from admin → AI provider.

    // Check if an AI provider is configured (needed to run analyses).
    const aiReady = await prisma.aIProvider.findFirst({
      where: { isActive: true, apiKeyEnc: { not: null } },
      select: { name: true },
    });

    if (!aiReady) {
      return NextResponse.json({
        configured: false,
        step: "ai",
        provider,
        adminEmail: admin.email,
      });
    }

    return NextResponse.json({
      configured: false,
      step: "complete",
      provider,
      adminEmail: admin.email,
      aiProvider: aiReady.name,
    });
  } catch {
    // DB not initialized or not accessible
    return NextResponse.json({
      configured: false,
      step: "database",
      provider: process.env.DATABASE_PROVIDER || "postgresql",
    });
  }
}

import { NextResponse } from "next/server";
import { getPrisma } from "@/lib/infrastructure/db-adapter";

export const dynamic = "force-dynamic";

/**
 * Check if setup is already complete.
 */
async function isSetupComplete(): Promise<boolean> {
  try {
    const client = getPrisma();
    const config = await client.systemConfig.findUnique({
      where: { key: "setup_complete" },
    });
    return config?.value === true;
  } catch {
    return false;
  }
}

/**
 * POST /api/setup/complete
 *
 * Marks the setup as complete:
 * - Sets SystemConfig `setup_complete` = true
 * - Removes the `setup_step` config (cleanup)
 * - Sets a cookie for the middleware to skip DB checks on future requests
 *
 * Returns: { success: boolean, error?: string }
 */
export async function POST() {
  try {
    // If already complete, just return success
    if (await isSetupComplete()) {
      const response = NextResponse.json({ success: true });
      response.cookies.set("aetheria_setup_complete", "true", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 60 * 60 * 24 * 365, // 1 year
        path: "/",
      });
      return response;
    }

    const client = getPrisma();

    // Mark setup as complete
    await client.systemConfig.upsert({
      where: { key: "setup_complete" },
      update: { value: true },
      create: { key: "setup_complete", value: true },
    });

    // Clean up setup_step
    await client.systemConfig.deleteMany({
      where: { key: "setup_step" },
    }).catch(() => {
      // Non-critical if deletion fails
    });

    // Create audit log for setup completion
    const admin = await client.user.findFirst({
      where: { isSystemAdmin: true },
      select: { id: true, companyId: true },
    });

    if (admin) {
      await client.auditLog.create({
        data: {
          action: "setup_complete",
          entityType: "SystemConfig",
          userId: admin.id,
          companyId: admin.companyId,
        },
      });
    }

    // Set cookie so middleware doesn't need to check DB on every request
    const response = NextResponse.json({ success: true });
    response.cookies.set("aetheria_setup_complete", "true", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24 * 365, // 1 year
      path: "/",
    });

    return response;
  } catch (error) {
    console.error("[SETUP] Complete error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

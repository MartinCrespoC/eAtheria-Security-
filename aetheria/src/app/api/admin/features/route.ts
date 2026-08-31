import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import {
  getAllFeatureFlags,
  setFeatureFlag,
  invalidateCache,
  FEATURES,
  type FeatureFlag,
} from "@/lib/infrastructure/feature-flags";

/**
 * GET /api/admin/features
 * Returns all feature flags with their current status.
 * Requires system admin.
 */
export async function GET() {
  try {
    await requireSystemAdmin();

    const flags = await getAllFeatureFlags();
    return NextResponse.json(flags);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    console.error("Error fetching feature flags:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * PUT /api/admin/features
 * Toggles a feature flag.
 * Body: { flag: string, enabled: boolean }
 * Requires system admin.
 */
export async function PUT(request: NextRequest) {
  try {
    await requireSystemAdmin();

    const body = await request.json();
    const { flag, enabled } = body as { flag: string; enabled: boolean };

    // Validate the flag is a known feature flag
    const validFlags = Object.values(FEATURES) as string[];
    if (!validFlags.includes(flag)) {
      return NextResponse.json(
        { error: `Invalid feature flag: ${flag}` },
        { status: 400 }
      );
    }

    if (typeof enabled !== "boolean") {
      return NextResponse.json(
        { error: "Field 'enabled' must be a boolean" },
        { status: 400 }
      );
    }

    await setFeatureFlag(flag as FeatureFlag, enabled);

    return NextResponse.json({
      success: true,
      flag,
      enabled,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    console.error("Error updating feature flag:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

/**
 * POST /api/admin/features/refresh
 * Invalidates the feature flag cache, forcing a refresh on next access.
 * Requires system admin.
 */
export async function POST() {
  try {
    await requireSystemAdmin();

    invalidateCache();

    return NextResponse.json({ success: true, message: "Cache invalidated" });
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED") {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }
    if (error instanceof Error && error.message === "FORBIDDEN") {
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    }
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

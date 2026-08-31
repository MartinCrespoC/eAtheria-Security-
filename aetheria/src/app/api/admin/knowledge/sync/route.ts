/**
 * Admin Knowledge Sync API
 * POST /api/admin/knowledge/sync - Trigger syncHuntSkills()
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { syncHuntSkills } from "@/lib/knowledge/sync";

export async function POST(req: NextRequest) {
  try {
    const session = await requireSystemAdmin();

    const body = await req.json().catch(() => ({}));
    const force = Boolean((body as { force?: boolean }).force);

    const stats = await syncHuntSkills({ force });

    return NextResponse.json({
      success: true,
      stats,
      message: `Sincronización completa: ${stats.created} skills procesados, ${stats.errors.length} errores`,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error en sincronización";
    console.error("Error syncing knowledge:", error);
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}

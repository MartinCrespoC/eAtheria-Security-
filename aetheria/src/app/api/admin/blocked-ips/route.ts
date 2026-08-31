import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

// Internal endpoint used by middleware to fetch blocked IPs
// Authenticated via internal key header
export async function GET(request: NextRequest) {
  const internalKey = request.headers.get("x-internal-key");
  if (internalKey !== process.env.NEXTAUTH_SECRET) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    // Read blocked IPs from system config
    const config = await prisma.systemConfig.findUnique({
      where: { key: "blocked_ips" },
    });

    const ips: string[] = config && Array.isArray(config.value) ? (config.value as string[]) : [];

    return NextResponse.json({ ips });
  } catch {
    return NextResponse.json({ ips: [] });
  }
}

// Admin endpoint to manage blocked IPs
export async function PUT(request: NextRequest) {
  const internalKey = request.headers.get("x-internal-key");
  const isInternal = internalKey === process.env.NEXTAUTH_SECRET;

  if (!isInternal) {
    // Check admin auth
    const { requireSystemAdmin } = await import("@/lib/auth");
    try {
      await requireSystemAdmin();
    } catch {
      return NextResponse.json({ error: "No autorizado" }, { status: 403 });
    }
  }

  try {
    const body = await request.json();
    const { ips } = body as { ips: string[] };

    if (!Array.isArray(ips)) {
      return NextResponse.json({ error: "IPs must be an array" }, { status: 400 });
    }

    await prisma.systemConfig.upsert({
      where: { key: "blocked_ips" },
      update: { value: ips as never },
      create: { key: "blocked_ips", value: ips as never },
    });

    return NextResponse.json({ success: true, count: ips.length });
  } catch (error) {
    console.error("Error updating blocked IPs:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

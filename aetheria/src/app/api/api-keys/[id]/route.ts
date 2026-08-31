import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { requirePermission } from "@/lib/security/permission-guard";
import { PERMISSIONS } from "@/lib/security/permissions";

// DELETE: Revoke an API key
export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const guard = await requirePermission(PERMISSIONS.INTEGRATIONS_MANAGE)(_req);
  if (!guard.ok) return guard.response;

  const session = await getServerSession(authOptions);
  if (!session?.user?.companyId) {
    return NextResponse.json({ error: "No autorizado" }, { status: 401 });
  }

  const { id } = await params;

  const apiKey = await prisma.apiKey.findFirst({
    where: { id, companyId: session.user.companyId },
  });

  if (!apiKey) {
    return NextResponse.json({ error: "API key no encontrada" }, { status: 404 });
  }

  await prisma.apiKey.update({
    where: { id },
    data: { isActive: false },
  });

  return NextResponse.json({ message: "API key revocada" });
}

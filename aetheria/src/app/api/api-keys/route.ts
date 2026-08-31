import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { generateApiKey } from "@/lib/crypto";
import { requirePermission } from "@/lib/security/permission-guard";
import { PERMISSIONS } from "@/lib/security/permissions";

// Only these scopes may be granted to API keys. Anything else (including
// "*") is rejected to prevent privilege escalation via wildcard keys.
const ALLOWED_SCOPES = ["analysis:create", "analysis:read"] as const;

// GET: List API keys for current company
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session?.user?.companyId) {
    return NextResponse.json({ error: "No autorizado" }, { status: 401 });
  }

  const keys = await prisma.apiKey.findMany({
    where: { companyId: session.user.companyId },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      scopes: true,
      lastUsedAt: true,
      expiresAt: true,
      isActive: true,
      createdAt: true,
      createdBy: { select: { firstName: true, lastName: true, email: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ keys });
}

// POST: Create a new API key
export async function POST(req: NextRequest) {
  const guard = await requirePermission(PERMISSIONS.INTEGRATIONS_MANAGE)(req);
  if (!guard.ok) return guard.response;

  const session = await getServerSession(authOptions);
  if (!session?.user?.companyId || !session.user.id) {
    return NextResponse.json({ error: "No autorizado" }, { status: 401 });
  }

  const body = await req.json();
  const { name, scopes, expiresInDays } = body;

  if (!name || typeof name !== "string") {
    return NextResponse.json(
      { error: "El nombre de la API key es requerido" },
      { status: 400 }
    );
  }

  if (
    scopes !== undefined &&
    (!Array.isArray(scopes) ||
      scopes.length === 0 ||
      scopes.some((s) => !ALLOWED_SCOPES.includes(s)))
  ) {
    return NextResponse.json(
      { error: `Scopes inválidos. Permitidos: ${ALLOWED_SCOPES.join(", ")}` },
      { status: 400 }
    );
  }

  // Max 10 API keys per company
  const count = await prisma.apiKey.count({
    where: { companyId: session.user.companyId, isActive: true },
  });

  if (count >= 10) {
    return NextResponse.json(
      { error: "Has alcanzado el límite de 10 API keys activas" },
      { status: 403 }
    );
  }

  const { key, prefix, hash } = generateApiKey();

  const expiresAt = expiresInDays
    ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  const apiKey = await prisma.apiKey.create({
    data: {
      name,
      keyHash: hash,
      keyPrefix: prefix,
      scopes: scopes || [...ALLOWED_SCOPES],
      companyId: session.user.companyId,
      createdById: session.user.id,
      expiresAt,
    },
  });

  // Return the raw key ONLY on creation (never again)
  return NextResponse.json(
    {
      id: apiKey.id,
      name: apiKey.name,
      key, // Only shown once!
      prefix: apiKey.keyPrefix,
      scopes: apiKey.scopes,
      expiresAt: apiKey.expiresAt,
      createdAt: apiKey.createdAt,
    },
    { status: 201 }
  );
}

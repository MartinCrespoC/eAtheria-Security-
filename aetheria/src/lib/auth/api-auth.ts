import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { hashApiKey } from "@/lib/crypto";

interface ApiKeyContext {
  companyId: string;
  apiKeyId: string;
  scopes: string[];
}

/**
 * Authenticate a request using Bearer API key.
 * Returns company context if valid, null if invalid.
 */
export async function authenticateApiKey(
  req: NextRequest
): Promise<ApiKeyContext | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer aeth_")) {
    return null;
  }

  const rawKey = authHeader.replace("Bearer ", "").trim();
  const keyHash = hashApiKey(rawKey);

  const apiKey = await prisma.apiKey.findUnique({
    where: { keyHash },
    include: { company: { select: { isActive: true } } },
  });

  if (!apiKey || !apiKey.isActive || !apiKey.company.isActive) {
    return null;
  }

  // Check expiration
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
    return null;
  }

  // Update last used timestamp (fire and forget)
  prisma.apiKey
    .update({
      where: { id: apiKey.id },
      data: { lastUsedAt: new Date() },
    })
    .catch(() => {});

  return {
    companyId: apiKey.companyId,
    apiKeyId: apiKey.id,
    scopes: apiKey.scopes as string[],
  };
}

export function hasScope(ctx: ApiKeyContext, scope: string): boolean {
  return ctx.scopes.includes(scope) || ctx.scopes.includes("*");
}

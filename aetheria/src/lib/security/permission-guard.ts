/**
 * Permission Guard for API Routes
 *
 * Provides a middleware-style helper that validates whether the authenticated
 * user has the required permissions before allowing access to a route handler.
 *
 * Works with both session-based auth and API key auth.
 */

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authenticateApiKey } from "@/lib/api-auth";
import {
  getUserEffectivePermissions,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
} from "@/lib/security/permissions";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";

export interface AuthContext {
  userId: string;
  companyId: string | null;
  isSystemAdmin: boolean;
  isCompanyAdmin: boolean;
  permissions: string[];
  authMethod: "session" | "api_key";
}

export interface PermissionCheckResult {
  ok: boolean;
  context?: AuthContext;
  response?: NextResponse;
}

/**
 * Resolve the authentication context from either a session or API key.
 * Returns the context with the user's effective permissions.
 */
export async function resolveAuthContext(
  req?: NextRequest
): Promise<AuthContext | null> {
  // 1. Try API key auth first
  if (req) {
    const apiKeyCtx = await authenticateApiKey(req);
    if (apiKeyCtx) {
      // For API key auth, we need to get the user's permissions from the created-by user
      const apiKey = await import("@/lib/db").then((m) =>
        m.prisma.apiKey.findUnique({
          where: { id: apiKeyCtx.apiKeyId },
          select: {
            createdById: true,
            company: {
              select: { id: true, isActive: true },
            },
          },
        })
      );

      if (apiKey && apiKey.company?.isActive) {
        const permissions = await getUserEffectivePermissions(
          apiKey.createdById,
          apiKeyCtx.companyId
        );

        const user = await import("@/lib/db").then((m) =>
          m.prisma.user.findUnique({
            where: { id: apiKey.createdById },
            select: { isSystemAdmin: true, isCompanyAdmin: true },
          })
        );

        return {
          userId: apiKey.createdById,
          companyId: apiKeyCtx.companyId,
          isSystemAdmin: user?.isSystemAdmin ?? false,
          isCompanyAdmin: user?.isCompanyAdmin ?? false,
          permissions,
          authMethod: "api_key",
        };
      }
    }
  }

  // 2. Fall back to session auth
  const session = await auth();
  if (!session?.user) return null;

  let permissions: string[] = [];
  if (session.user.companyId) {
    permissions = await getUserEffectivePermissions(
      session.user.id,
      session.user.companyId
    );
  } else if (session.user.isSystemAdmin) {
    // System admins get all permissions
    permissions = await import("@/lib/security/permissions").then((m) =>
      Object.values(m.PERMISSIONS)
    );
  }

  return {
    userId: session.user.id,
    companyId: session.user.companyId ?? null,
    isSystemAdmin: session.user.isSystemAdmin,
    isCompanyAdmin: session.user.isCompanyAdmin,
    permissions,
    authMethod: "session",
  };
}

/**
 * Require a single permission.
 * Returns the auth context if authorized, or a 403 NextResponse if not.
 *
 * Usage in API routes:
 * ```ts
 * const guard = await requirePermission(PERMISSIONS.SETTINGS_UPDATE)(req);
 * if (!guard.ok) return guard.response;
 * const { context } = guard;
 * ```
 */
export function requirePermission(permission: string) {
  return async (req?: NextRequest): Promise<PermissionCheckResult> => {
    const context = await resolveAuthContext(req);

    if (!context) {
      return {
        ok: false,
        response: NextResponse.json(
          { error: "No autorizado" },
          { status: 401 }
        ),
      };
    }

    // System admins bypass permission checks
    if (context.isSystemAdmin) {
      return { ok: true, context };
    }

    if (!hasPermission(context.permissions, permission)) {
      await logAudit({
        action: AuditAction.ACCESS_DENIED,
        severity: AuditSeverity.WARNING,
        userId: context.userId,
        companyId: context.companyId ?? undefined,
        metadata: {
          requiredPermission: permission,
          authMethod: context.authMethod,
        },
        success: false,
      });

      return {
        ok: false,
        response: NextResponse.json(
          { error: "Acceso denegado" },
          { status: 403 }
        ),
      };
    }

    return { ok: true, context };
  };
}

/**
 * Require ANY of the listed permissions.
 */
export function requireAnyPermission(...permissions: string[]) {
  return async (req?: NextRequest): Promise<PermissionCheckResult> => {
    const context = await resolveAuthContext(req);

    if (!context) {
      return {
        ok: false,
        response: NextResponse.json(
          { error: "No autorizado" },
          { status: 401 }
        ),
      };
    }

    if (context.isSystemAdmin) {
      return { ok: true, context };
    }

    if (!hasAnyPermission(context.permissions, permissions)) {
      await logAudit({
        action: AuditAction.ACCESS_DENIED,
        severity: AuditSeverity.WARNING,
        userId: context.userId,
        companyId: context.companyId ?? undefined,
        metadata: {
          requiredPermissions: permissions,
          authMethod: context.authMethod,
        },
        success: false,
      });

      return {
        ok: false,
        response: NextResponse.json(
          { error: "Acceso denegado" },
          { status: 403 }
        ),
      };
    }

    return { ok: true, context };
  };
}

/**
 * Require ALL of the listed permissions.
 */
export function requireAllPermissions(...permissions: string[]) {
  return async (req?: NextRequest): Promise<PermissionCheckResult> => {
    const context = await resolveAuthContext(req);

    if (!context) {
      return {
        ok: false,
        response: NextResponse.json(
          { error: "No autorizado" },
          { status: 401 }
        ),
      };
    }

    if (context.isSystemAdmin) {
      return { ok: true, context };
    }

    if (!hasAllPermissions(context.permissions, permissions)) {
      await logAudit({
        action: AuditAction.ACCESS_DENIED,
        severity: AuditSeverity.WARNING,
        userId: context.userId,
        companyId: context.companyId ?? undefined,
        metadata: {
          requiredPermissions: permissions,
          authMethod: context.authMethod,
        },
        success: false,
      });

      return {
        ok: false,
        response: NextResponse.json(
          { error: "Acceso denegado" },
          { status: 403 }
        ),
      };
    }

    return { ok: true, context };
  };
}


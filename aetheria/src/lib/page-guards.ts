/**
 * Server-Side Page Guards
 * These run ONLY on the server (Next.js Server Components).
 * They CANNOT be bypassed by editing client-side JS/HTML.
 *
 * Usage in page.tsx:
 *   import { requireSystemAdmin, requirePermission } from "@/lib/page-guards";
 *   export default async function Page() {
 *     const session = await requireSystemAdmin(); // redirects if unauthorized
 *     // ... render admin content
 *   }
 */

import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { getUserEffectivePermissions } from "@/lib/security/permissions";

/**
 * Require authenticated user. Redirects to /login if not authenticated.
 */
export async function requireAuth() {
  const session = await auth();
  if (!session?.user) redirect("/login");
  return session;
}

/**
 * Require a specific granular permission.
 * Checks the user's effective permissions from their roles in the DB.
 * Redirects to /dashboard if the user lacks the permission.
 *
 * Individual mode: single workspace — system admins have all permissions.
 *
 * @param permission - e.g. "settings:update", "team:manage"
 */
export async function requirePermission(permission: string) {
  const session = await requireAuth();

  // System admins have all permissions
  if (session.user.isSystemAdmin) return session;

  // Check granular permissions from DB roles (only for non-admin users)
  const permissions = await getUserEffectivePermissions(
    session.user.id,
    session.user.companyId!
  );

  if (!permissions.includes(permission)) {
    redirect("/dashboard");
  }

  return session;
}

/**
 * Require ANY of the listed permissions.
 */
export async function requireAnyPermission(...perms: string[]) {
  const session = await requireAuth();

  if (session.user.isSystemAdmin) return session;

  const permissions = await getUserEffectivePermissions(
    session.user.id,
    session.user.companyId!
  );

  if (!perms.some((p) => permissions.includes(p))) {
    redirect("/dashboard");
  }

  return session;
}

/**
 * Require system admin. Redirects to /dashboard if not system admin.
 * (Used for /admin/* pages — already enforced by middleware, this is defense-in-depth)
 */
export async function requireSystemAdmin() {
  const session = await requireAuth();
  if (!session.user.isSystemAdmin) redirect("/dashboard");
  return session;
}

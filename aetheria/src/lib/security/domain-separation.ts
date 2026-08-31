/**
 * Domain Separation Utilities
 * Ensures complete data isolation between companies
 */

import { auth } from "@/lib/auth";
import { logAudit, AuditAction, AuditSeverity } from "./audit-logger";

/**
 * Get current user's company ID with validation
 * Throws error if user has no company (except system admins)
 */
export async function requireCompanyId(): Promise<string> {
  const session = await auth();
  
  if (!session?.user) {
    throw new Error("UNAUTHORIZED");
  }

  // System admins can operate without a company
  if (session.user.isSystemAdmin) {
    throw new Error("SYSTEM_ADMIN_NO_COMPANY");
  }

  if (!session.user.companyId) {
    throw new Error("NO_COMPANY_ASSIGNED");
  }

  return session.user.companyId;
}

/**
 * Validate that a resource belongs to the user's company
 * Returns true if valid, throws error if not
 */
export async function validateCompanyAccess(
  resourceCompanyId: string | null | undefined,
  resourceType: string,
  resourceId: string
): Promise<boolean> {
  const session = await auth();
  
  if (!session?.user) {
    throw new Error("UNAUTHORIZED");
  }

  // System admins can access any company
  if (session.user.isSystemAdmin) {
    return true;
  }

  // Check if resource belongs to user's company
  if (resourceCompanyId !== session.user.companyId) {
    // Log security violation
    await logAudit({
      userId: session.user.id,
      companyId: session.user.companyId,
      action: AuditAction.IDOR_ATTEMPT,
      severity: AuditSeverity.CRITICAL,
      metadata: {
        resourceType,
        resourceId,
        resourceCompanyId,
        userCompanyId: session.user.companyId,
      },
      success: false,
    });

    throw new Error("FORBIDDEN");
  }

  return true;
}

/**
 * Get Prisma where clause with company isolation
 * Automatically adds companyId filter for non-system-admins
 */
export async function getCompanyWhereClause(): Promise<{ companyId?: string }> {
  const session = await auth();
  
  if (!session?.user) {
    throw new Error("UNAUTHORIZED");
  }

  // System admins see all companies
  if (session.user.isSystemAdmin) {
    return {};
  }

  // Regular users only see their company
  if (!session.user.companyId) {
    throw new Error("NO_COMPANY_ASSIGNED");
  }

  return { companyId: session.user.companyId };
}

/**
 * Validate that user can create resources for a company
 */
export async function validateCompanyCreate(targetCompanyId: string): Promise<boolean> {
  const session = await auth();
  
  if (!session?.user) {
    throw new Error("UNAUTHORIZED");
  }

  // System admins can create for any company
  if (session.user.isSystemAdmin) {
    return true;
  }

  // Company admins can only create for their own company
  if (session.user.isCompanyAdmin && targetCompanyId === session.user.companyId) {
    return true;
  }

  // Regular users cannot create for other companies
  if (targetCompanyId !== session.user.companyId) {
    await logAudit({
      userId: session.user.id,
      companyId: session.user.companyId,
      action: AuditAction.PRIVILEGE_ESCALATION_ATTEMPT,
      severity: AuditSeverity.CRITICAL,
      metadata: {
        attemptedCompanyId: targetCompanyId,
        userCompanyId: session.user.companyId,
      },
      success: false,
    });

    throw new Error("FORBIDDEN");
  }

  return true;
}

/**
 * Check if user is system admin
 */
export async function isSystemAdmin(): Promise<boolean> {
  const session = await auth();
  return session?.user?.isSystemAdmin || false;
}

/**
 * Check if user is company admin
 */
export async function isCompanyAdmin(): Promise<boolean> {
  const session = await auth();
  return session?.user?.isCompanyAdmin || false;
}

/**
 * Get user's effective permissions
 */
export async function getUserPermissions() {
  const session = await auth();
  
  if (!session?.user) {
    return {
      isSystemAdmin: false,
      isCompanyAdmin: false,
      companyId: null,
      canAccessAllCompanies: false,
      canManageCompany: false,
    };
  }

  return {
    isSystemAdmin: session.user.isSystemAdmin || false,
    isCompanyAdmin: session.user.isCompanyAdmin || false,
    companyId: session.user.companyId || null,
    canAccessAllCompanies: session.user.isSystemAdmin || false,
    canManageCompany: session.user.isSystemAdmin || session.user.isCompanyAdmin || false,
  };
}

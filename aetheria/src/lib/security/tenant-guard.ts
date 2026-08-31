/**
 * Tenant Guard - Enhanced Tenant Isolation Utilities
 *
 * Provides company-level rate limiting, cross-company access auditing,
 * API key company validation, and session timeout enforcement.
 */

import { prisma } from "@/lib/db";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";
import { authenticateApiKey } from "@/lib/api-auth";

// Company rate limiting lives in an Edge-safe module so the middleware can
// import it without pulling Node-only dependencies (prisma/crypto) into the
// Edge Runtime. Re-exported here for backwards compatibility.
export {
  checkCompanyRateLimit,
  checkCompanyRateLimitWithMax,
  resetCompanyRateLimits,
  getCompanyRateLimitStats,
} from "@/lib/security/company-rate-limit";

/**
 * Audit a cross-company access attempt.
 * Logs the event with full context for security analysis.
 */
export async function auditCrossCompanyAccess(
  userId: string,
  attemptedCompanyId: string,
  endpoint: string
): Promise<void> {
  // Get the user's actual company for context
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { companyId: true, email: true },
  });

  await logAudit({
    action: AuditAction.IDOR_ATTEMPT,
    severity: AuditSeverity.CRITICAL,
    userId,
    companyId: user?.companyId ?? undefined,
    metadata: {
      attemptedCompanyId,
      userCompanyId: user?.companyId ?? null,
      endpoint,
      userEmail: user?.email,
      eventType: "cross_company_access",
    },
    success: false,
  });

  // Console alert for immediate visibility
  console.error(
    `[TENANT GUARD] Cross-company access attempt by user ${userId} (${user?.email}) ` +
      `from company ${user?.companyId} to company ${attemptedCompanyId} on endpoint ${endpoint}`
  );
}

/**
 * Validate that an API key belongs to the correct company.
 * Prevents using an API key from company A to access company B's data.
 */
export async function validateApiKeyCompany(
  apiKeyRaw: string,
  requestedCompanyId: string
): Promise<boolean> {
  const { hashApiKey } = await import("@/lib/crypto");
  const keyHash = hashApiKey(apiKeyRaw);

  const apiKey = await prisma.apiKey.findUnique({
    where: { keyHash },
    select: { companyId: true, isActive: true },
  });

  if (!apiKey || !apiKey.isActive) {
    return false;
  }

  if (apiKey.companyId !== requestedCompanyId) {
    // Log the cross-company API key attempt
    await logAudit({
      action: AuditAction.IDOR_ATTEMPT,
      severity: AuditSeverity.CRITICAL,
      metadata: {
        apiKeyCompanyId: apiKey.companyId,
        requestedCompanyId,
        eventType: "api_key_company_mismatch",
      },
      success: false,
    });
    return false;
  }

  return true;
}

/**
 * Check if a session has expired based on the company's timeout setting.
 */
export function isSessionExpired(
  lastActivity: Date,
  companyTimeoutMinutes: number
): boolean {
  const now = Date.now();
  const lastActivityMs = lastActivity.getTime();
  const timeoutMs = companyTimeoutMinutes * 60 * 1000;

  return now - lastActivityMs > timeoutMs;
}

/**
 * Get company settings for rate limiting and session timeout.
 * Returns default values if settings don't exist.
 */
export async function getCompanySecuritySettings(companyId: string): Promise<{
  rateLimitPerMinute: number;
  sessionTimeoutMinutes: number;
  maxLoginAttempts: number;
  requireTwoFactor: boolean;
}> {
  const settings = await prisma.companySettings.findUnique({
    where: { companyId },
    select: {
      rateLimitPerMinute: true,
      sessionTimeoutMinutes: true,
      maxLoginAttempts: true,
      requireTwoFactor: true,
    },
  });

  if (!settings) {
    return {
      rateLimitPerMinute: 60,
      sessionTimeoutMinutes: 480, // 8 hours
      maxLoginAttempts: 5,
      requireTwoFactor: false,
    };
  }

  return settings;
}

/**
 * Ensure CompanySettings exists for a company.
 * Creates with default values if missing.
 */
export async function ensureCompanySettings(
  companyId: string
): Promise<void> {
  const existing = await prisma.companySettings.findUnique({
    where: { companyId },
    select: { id: true },
  });

  if (!existing) {
    await prisma.companySettings.create({
      data: { companyId },
    });
  }
}

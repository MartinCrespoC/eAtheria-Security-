/**
 * Comprehensive Audit Logging System
 * Tracks all security-relevant events for compliance and forensics
 */

import { prisma } from "@/lib/db";

export enum AuditAction {
  // Authentication
  LOGIN_SUCCESS = "auth.login.success",
  LOGIN_FAILURE = "auth.login.failure",
  LOGOUT = "auth.logout",
  REGISTER = "auth.register",
  PASSWORD_CHANGE = "auth.password.change",
  PASSWORD_RESET = "auth.password.reset",
  TWO_FA_ENABLE = "auth.2fa.enable",
  TWO_FA_DISABLE = "auth.2fa.disable",

  // Authorization
  ACCESS_DENIED = "authz.access.denied",
  PRIVILEGE_ESCALATION_ATTEMPT = "authz.privilege_escalation.attempt",
  IDOR_ATTEMPT = "authz.idor.attempt",

  // Resource Management
  RESOURCE_CREATE = "resource.create",
  RESOURCE_READ = "resource.read",
  RESOURCE_UPDATE = "resource.update",
  RESOURCE_DELETE = "resource.delete",

  // Admin Actions
  ADMIN_CONFIG_CHANGE = "admin.config.change",
  ADMIN_USER_CREATE = "admin.user.create",
  ADMIN_USER_UPDATE = "admin.user.update",
  ADMIN_USER_DELETE = "admin.user.delete",
  ADMIN_ROLE_CHANGE = "admin.role.change",

  // Company Management
  COMPANY_CREATED = "company.created",
  COMPANY_UPDATED = "company.updated",
  COMPANY_DELETED = "company.deleted",

  // Security Events
  RATE_LIMIT_EXCEEDED = "security.rate_limit.exceeded",
  IP_BLOCKED = "security.ip.blocked",
  SUSPICIOUS_ACTIVITY = "security.suspicious.activity",
  API_KEY_CREATED = "security.api_key.created",
  API_KEY_DELETED = "security.api_key.deleted",

  // Data Access
  SENSITIVE_DATA_ACCESS = "data.sensitive.access",
  BULK_EXPORT = "data.bulk.export",

  // System
  SYSTEM_ERROR = "system.error",
  SYSTEM_CONFIG_CHANGE = "system.config.change",
}

export enum AuditSeverity {
  INFO = "INFO",
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  WARNING = "WARNING",
  ERROR = "ERROR",
  CRITICAL = "CRITICAL",
}

export interface AuditLogEntry {
  action: AuditAction;
  severity: AuditSeverity;
  userId?: string;
  companyId?: string | null;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  details?: Record<string, unknown>;
  success?: boolean;
  errorMessage?: string;
}

/**
 * Log an audit event
 */
export async function logAudit(entry: AuditLogEntry): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        action: entry.action,
        userId: entry.userId,
        companyId: entry.companyId,
        entityType: entry.resourceType,
        entityId: entry.resourceId,
        ipAddress: entry.ipAddress,
        userAgent: entry.userAgent,
        newValues: {
          severity: entry.severity,
          ...(entry.details || {}),
          ...(entry.metadata || {}),
          ...(entry.success !== undefined ? { success: entry.success } : {}),
          ...(entry.errorMessage ? { errorMessage: entry.errorMessage } : {}),
        } as never,
      },
    });

    // For critical events, also log to console for immediate visibility
    if (entry.severity === AuditSeverity.CRITICAL) {
      console.error("[AUDIT CRITICAL]", {
        action: entry.action,
        userId: entry.userId,
        resourceId: entry.resourceId,
        error: entry.errorMessage,
      });
    }
  } catch (error) {
    // Audit logging should never break the application
    console.error("[AUDIT LOG ERROR]", error);
  }
}

/**
 * Helper functions for common audit scenarios
 */

export async function logLoginAttempt(
  email: string,
  success: boolean,
  ipAddress: string,
  userAgent: string,
  userId?: string,
  errorMessage?: string
): Promise<void> {
  await logAudit({
    action: success ? AuditAction.LOGIN_SUCCESS : AuditAction.LOGIN_FAILURE,
    severity: success ? AuditSeverity.INFO : AuditSeverity.WARNING,
    userId,
    ipAddress,
    userAgent,
    metadata: { email },
    success,
    errorMessage,
  });
}

export async function logAccessDenied(
  userId: string,
  resourceType: string,
  resourceId: string,
  ipAddress: string,
  reason: string
): Promise<void> {
  await logAudit({
    action: AuditAction.ACCESS_DENIED,
    severity: AuditSeverity.WARNING,
    userId,
    resourceType,
    resourceId,
    ipAddress,
    metadata: { reason },
    success: false,
  });
}

export async function logPrivilegeEscalationAttempt(
  userId: string,
  companyId: string | null,
  attemptedAction: string,
  ipAddress: string
): Promise<void> {
  await logAudit({
    action: AuditAction.PRIVILEGE_ESCALATION_ATTEMPT,
    severity: AuditSeverity.CRITICAL,
    userId,
    companyId: companyId || undefined,
    ipAddress,
    metadata: { attemptedAction },
    success: false,
    errorMessage: "Unauthorized privilege escalation attempt detected",
  });
}

export async function logAdminAction(
  action: AuditAction,
  userId: string,
  resourceType: string,
  resourceId: string,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logAudit({
    action,
    severity: AuditSeverity.INFO,
    userId,
    resourceType,
    resourceId,
    metadata,
    success: true,
  });
}

export async function logResourceAccess(
  action: AuditAction,
  userId: string,
  companyId: string | null,
  resourceType: string,
  resourceId: string,
  success: boolean = true
): Promise<void> {
  await logAudit({
    action,
    severity: success ? AuditSeverity.INFO : AuditSeverity.WARNING,
    userId,
    companyId: companyId || undefined,
    resourceType,
    resourceId,
    success,
  });
}

export async function logSuspiciousActivity(
  userId: string | undefined,
  ipAddress: string,
  activityType: string,
  details: Record<string, unknown>
): Promise<void> {
  await logAudit({
    action: AuditAction.SUSPICIOUS_ACTIVITY,
    severity: AuditSeverity.CRITICAL,
    userId,
    ipAddress,
    metadata: { activityType, ...details },
    success: false,
  });
}

/**
 * Query audit logs for security analysis
 */
export async function getAuditLogs(filters: {
  userId?: string;
  companyId?: string;
  action?: AuditAction;
  severity?: AuditSeverity;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
}) {
  return prisma.auditLog.findMany({
    where: {
      userId: filters.userId,
      companyId: filters.companyId,
      action: filters.action,
      createdAt: {
        gte: filters.startDate,
        lte: filters.endDate,
      },
    },
    orderBy: { createdAt: "desc" },
    take: filters.limit || 100,
  });
}

/**
 * Get security alerts (failed logins, access denials, etc.)
 */
export async function getSecurityAlerts(hours: number = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  return prisma.auditLog.findMany({
    where: {
      createdAt: { gte: since },
      OR: [
        { action: AuditAction.LOGIN_FAILURE },
        { action: AuditAction.ACCESS_DENIED },
        { action: AuditAction.PRIVILEGE_ESCALATION_ATTEMPT },
        { action: AuditAction.IDOR_ATTEMPT },
        { action: AuditAction.SUSPICIOUS_ACTIVITY },
      ],
    },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
}

/**
 * Security Module — Barrel Export
 *
 * Centralizes all security-related exports:
 * - Cryptographic utilities (encryption, hashing, token generation)
 * - Rate limiting (in-memory & Redis-backed)
 * - Audit logging
 * - Domain separation (tenant isolation)
 * - IDOR protection
 * - Permission guard (RBAC enforcement)
 * - Granular permissions system
 * - Tenant guard (per-company rate limits & security settings)
 * - Isolation testing
 */

// Cryptography
export {
  encrypt,
  decrypt,
  hashPassword,
  verifyPassword,
  generateSecureToken,
  generateApiKey,
  hashApiKey,
} from "./crypto";

export { hashPasswordClient } from "./crypto-client";

// Rate limiting — Redis-backed
export { rateLimit, rateLimitRedis, getClientIp } from "./rate-limit";
export type { RateLimitOptions, RateLimitResult } from "./rate-limit";

// Rate limiting — in-memory sliding window
export { checkRateLimit, resetRateLimit, getRateLimitStats } from "./rate-limiter";

// Audit logging
export {
  AuditAction,
  AuditSeverity,
  logAudit,
  logLoginAttempt,
  logAccessDenied,
  logPrivilegeEscalationAttempt,
  logAdminAction,
  logResourceAccess,
  logSuspiciousActivity,
  getAuditLogs,
  getSecurityAlerts,
} from "./audit-logger";
export type { AuditLogEntry } from "./audit-logger";

// Domain separation (tenant isolation)
export {
  requireCompanyId,
  validateCompanyAccess,
  getCompanyWhereClause,
  validateCompanyCreate,
  isSystemAdmin,
  isCompanyAdmin,
  getUserPermissions,
} from "./domain-separation";

// IDOR protection
export {
  IDORError,
  verifyResourceOwnership,
  requireResourceOwnership,
} from "./idor-protection";

// Permission guard (RBAC enforcement middleware)
export {
  resolveAuthContext,
  requirePermission,
  requireAnyPermission,
  requireAllPermissions,
} from "./permission-guard";
export type { AuthContext, PermissionCheckResult } from "./permission-guard";

// Granular permissions system
export {
  PERMISSIONS,
  PERMISSION_CATEGORIES,
  DEFAULT_ROLES,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getUserEffectivePermissions,
  ensureDefaultRoles,
  getDefaultRole,
} from "./permissions";
export type { Permission } from "./permissions";

// Tenant guard
export {
  checkCompanyRateLimit,
  checkCompanyRateLimitWithMax,
  auditCrossCompanyAccess,
  validateApiKeyCompany,
  isSessionExpired,
  getCompanySecuritySettings,
  ensureCompanySettings,
  resetCompanyRateLimits,
  getCompanyRateLimitStats,
} from "./tenant-guard";


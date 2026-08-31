/**
 * Business Module — Barrel Export
 *
 * Individual mode: only legacy permissions (ROLE_TEMPLATES for setup).
 * Granular RBAC permissions live in @/lib/security.
 */

// Legacy permissions (ROLE_TEMPLATES)
// The granular RBAC system with DEFAULT_ROLES lives in @/lib/security/permissions
export {
  PERMISSIONS,
  ROLE_TEMPLATES,
  hasPermission,
  hasAnyPermission,
} from "./permissions";
export type { Permission } from "./permissions";

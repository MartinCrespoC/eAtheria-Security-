/**
 * Re-export proxy — actual implementation lives in ./business/permissions.ts
 * This is the legacy permission system with ROLE_TEMPLATES.
 * The granular RBAC system lives in ./security/permissions.ts.
 */
export {
  PERMISSIONS,
  ROLE_TEMPLATES,
  hasPermission,
  hasAnyPermission,
} from "./business/permissions";
export type { Permission } from "./business/permissions";

/**
 * Granular Permissions System
 * Central definition of all permission strings, default role templates,
 * and helper functions for permission checking.
 *
 * Works in conjunction with the RBAC system (Role + UserRole models in Prisma).
 */

import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";

// ==================== PERMISSION CONSTANTS ====================

export const PERMISSIONS = {
  // Scans / Analysis
  SCAN_CREATE: "scan:create",
  SCAN_READ: "scan:read",
  SCAN_DELETE: "scan:delete",

  // Applications
  APP_CREATE: "app:create",
  APP_READ: "app:read",
  APP_UPDATE: "app:update",
  APP_DELETE: "app:delete",

  // Team management
  TEAM_INVITE: "team:invite",
  TEAM_MANAGE: "team:manage",
  TEAM_REMOVE: "team:remove",

  // Company settings
  SETTINGS_READ: "settings:read",
  SETTINGS_UPDATE: "settings:update",

  // AI configuration & usage
  AI_CONFIGURE: "ai:configure",
  AI_USE: "ai:use",

  // Integrations (GitHub, GitLab, CI/CD)
  INTEGRATIONS_MANAGE: "integrations:manage",

  // Billing
  BILLING_READ: "billing:read",
  BILLING_MANAGE: "billing:manage",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

// ==================== PERMISSION CATEGORIES ====================

export const PERMISSION_CATEGORIES: {
  label: string;
  permissions: { key: string; label: string }[];
}[] = [
  {
    label: "Scans & Analysis",
    permissions: [
      { key: PERMISSIONS.SCAN_CREATE, label: "Create scans" },
      { key: PERMISSIONS.SCAN_READ, label: "View scans" },
      { key: PERMISSIONS.SCAN_DELETE, label: "Delete scans" },
    ],
  },
  {
    label: "Applications",
    permissions: [
      { key: PERMISSIONS.APP_CREATE, label: "Create applications" },
      { key: PERMISSIONS.APP_READ, label: "View applications" },
      { key: PERMISSIONS.APP_UPDATE, label: "Update applications" },
      { key: PERMISSIONS.APP_DELETE, label: "Delete applications" },
    ],
  },
  {
    label: "Team Management",
    permissions: [
      { key: PERMISSIONS.TEAM_INVITE, label: "Invite members" },
      { key: PERMISSIONS.TEAM_MANAGE, label: "Manage members" },
      { key: PERMISSIONS.TEAM_REMOVE, label: "Remove members" },
    ],
  },
  {
    label: "Company Settings",
    permissions: [
      { key: PERMISSIONS.SETTINGS_READ, label: "View settings" },
      { key: PERMISSIONS.SETTINGS_UPDATE, label: "Update settings" },
    ],
  },
  {
    label: "Artificial Intelligence",
    permissions: [
      { key: PERMISSIONS.AI_CONFIGURE, label: "Configure AI" },
      { key: PERMISSIONS.AI_USE, label: "Use AI features" },
    ],
  },
  {
    label: "Integrations",
    permissions: [
      { key: PERMISSIONS.INTEGRATIONS_MANAGE, label: "Manage integrations" },
    ],
  },
  {
    label: "Billing",
    permissions: [
      { key: PERMISSIONS.BILLING_READ, label: "View billing" },
      { key: PERMISSIONS.BILLING_MANAGE, label: "Manage billing" },
    ],
  },
];

// ==================== DEFAULT ROLE TEMPLATES ====================

export const DEFAULT_ROLES: Record<string, {
  name: string;
  displayName: string;
  description: string;
  permissions: string[];
  isDefault?: boolean;
}> = {
  COMPANY_ADMIN: {
    name: "admin",
    displayName: "Company Admin",
    description: "Full access to all company features and settings",
    permissions: Object.values(PERMISSIONS),
    isDefault: true,
  },
  DEVELOPER: {
    name: "developer",
    displayName: "Developer",
    description: "Can create scans and manage applications",
    permissions: [
      PERMISSIONS.SCAN_CREATE,
      PERMISSIONS.SCAN_READ,
      PERMISSIONS.APP_CREATE,
      PERMISSIONS.APP_READ,
      PERMISSIONS.APP_UPDATE,
      PERMISSIONS.AI_USE,
      PERMISSIONS.SETTINGS_READ,
    ],
  },
  VIEWER: {
    name: "viewer",
    displayName: "Viewer",
    description: "Read-only access to scans and applications",
    permissions: [
      PERMISSIONS.SCAN_READ,
      PERMISSIONS.APP_READ,
      PERMISSIONS.SETTINGS_READ,
      PERMISSIONS.BILLING_READ,
    ],
  },
  SECURITY_ANALYST: {
    name: "security_analyst",
    displayName: "Security Analyst",
    description: "Can create and delete scans, use AI features",
    permissions: [
      PERMISSIONS.SCAN_CREATE,
      PERMISSIONS.SCAN_READ,
      PERMISSIONS.SCAN_DELETE,
      PERMISSIONS.APP_READ,
      PERMISSIONS.AI_USE,
    ],
  },
};

// ==================== HELPER FUNCTIONS ====================

/**
 * Check if user has a single permission.
 */
export function hasPermission(
  userPermissions: string[],
  required: string
): boolean {
  return userPermissions.includes(required);
}

/**
 * Check if user has any of the listed permissions.
 */
export function hasAnyPermission(
  userPermissions: string[],
  required: string[]
): boolean {
  return required.some((p) => userPermissions.includes(p));
}

/**
 * Check if user has ALL of the listed permissions.
 */
export function hasAllPermissions(
  userPermissions: string[],
  required: string[]
): boolean {
  return required.every((p) => userPermissions.includes(p));
}

/**
 * Get the effective permissions for a user in a company.
 * Combines permissions from all roles the user has.
 * System admins implicitly have all permissions.
 * Company admins implicitly have all permissions.
 */
export async function getUserEffectivePermissions(
  userId: string,
  companyId: string
): Promise<string[]> {
  // Fetch user with roles
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      isSystemAdmin: true,
      isCompanyAdmin: true,
      companyId: true,
      userRoles: {
        include: {
          role: {
            select: { permissions: true, companyId: true },
          },
        },
      },
    },
  });

  if (!user) {
    return [];
  }

  // System admins have all permissions
  if (user.isSystemAdmin) {
    return Object.values(PERMISSIONS);
  }

  // Company admins have all permissions (only for their own company)
  if (user.isCompanyAdmin && user.companyId === companyId) {
    return Object.values(PERMISSIONS);
  }

  // Aggregate permissions from all roles that belong to this company
  const permissionSet = new Set<string>();
  for (const userRole of user.userRoles) {
    // Only count roles from the same company
    if (userRole.role.companyId === companyId) {
      const perms = userRole.role.permissions;
      if (Array.isArray(perms)) {
        for (const p of perms) {
          if (typeof p === "string") {
            permissionSet.add(p);
          }
        }
      }
    }
  }

  return Array.from(permissionSet);
}

/**
 * Ensure default roles exist for a company.
 * Called when a company is created or when roles are first accessed.
 */
export async function ensureDefaultRoles(
  companyId: string
): Promise<void> {
  const existingRoles = await prisma.role.findMany({
    where: { companyId },
    select: { name: true },
  });

  const existingNames = new Set(existingRoles.map((r) => r.name));

  const rolesToCreate = Object.values(DEFAULT_ROLES).filter(
    (template) => !existingNames.has(template.name)
  );

  if (rolesToCreate.length === 0) return;

  await prisma.role.createMany({
    data: rolesToCreate.map((template) => ({
      name: template.name,
      displayName: template.displayName,
      description: template.description,
      permissions: template.permissions,
      isDefault: template.isDefault ?? false,
      companyId,
    })),
  });
}

/**
 * Get the default role for new users in a company.
 * Falls back to the 'viewer' role if no default is set.
 */
export async function getDefaultRole(
  companyId: string
): Promise<string | null> {
  const defaultRole = await prisma.role.findFirst({
    where: { companyId, isDefault: true },
    select: { id: true },
  });

  if (defaultRole) return defaultRole.id;

  // Fallback: find the 'viewer' role
  const viewerRole = await prisma.role.findFirst({
    where: { companyId, name: "viewer" },
    select: { id: true },
  });

  return viewerRole?.id ?? null;
}

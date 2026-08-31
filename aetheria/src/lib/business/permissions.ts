export const PERMISSIONS = {
  // Company management
  COMPANY_VIEW: "company:view",
  COMPANY_EDIT: "company:edit",
  COMPANY_DELETE: "company:delete",

  // User management
  USER_VIEW: "user:view",
  USER_CREATE: "user:create",
  USER_EDIT: "user:edit",
  USER_DELETE: "user:delete",

  // Role management
  ROLE_VIEW: "role:view",
  ROLE_CREATE: "role:create",
  ROLE_EDIT: "role:edit",
  ROLE_DELETE: "role:delete",

  // Application management
  APP_VIEW: "app:view",
  APP_CREATE: "app:create",
  APP_EDIT: "app:edit",
  APP_DELETE: "app:delete",

  // Analysis
  ANALYSIS_VIEW: "analysis:view",
  ANALYSIS_CREATE: "analysis:create",
  ANALYSIS_DELETE: "analysis:delete",

  // Vulnerabilities
  VULN_VIEW: "vuln:view",
  VULN_EDIT: "vuln:edit",
  VULN_EXPORT: "vuln:export",

  // GitHub integration
  GITHUB_CONNECT: "github:connect",
  GITHUB_SYNC: "github:sync",

  // Billing
  BILLING_VIEW: "billing:view",
  BILLING_MANAGE: "billing:manage",

  // Settings
  SETTINGS_VIEW: "settings:view",
  SETTINGS_EDIT: "settings:edit",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const ROLE_TEMPLATES = {
  COMPANY_ADMIN: {
    name: "admin",
    displayName: "Administrador",
    description: "Acceso completo a la empresa",
    permissions: Object.values(PERMISSIONS),
  },
  COMPANY_VIEWER: {
    name: "viewer",
    displayName: "Viewer",
    description: "Solo lectura",
    permissions: [
      PERMISSIONS.COMPANY_VIEW,
      PERMISSIONS.APP_VIEW,
      PERMISSIONS.ANALYSIS_VIEW,
      PERMISSIONS.VULN_VIEW,
    ],
  },
  COMPANY_DEVELOPER: {
    name: "developer",
    displayName: "Developer",
    description: "Puede ejecutar análisis y ver vulnerabilidades",
    permissions: [
      PERMISSIONS.COMPANY_VIEW,
      PERMISSIONS.APP_VIEW,
      PERMISSIONS.APP_CREATE,
      PERMISSIONS.APP_EDIT,
      PERMISSIONS.ANALYSIS_VIEW,
      PERMISSIONS.ANALYSIS_CREATE,
      PERMISSIONS.VULN_VIEW,
      PERMISSIONS.VULN_EDIT,
      PERMISSIONS.GITHUB_CONNECT,
      PERMISSIONS.GITHUB_SYNC,
    ],
  },
};

export function hasPermission(
  userPermissions: string[],
  required: Permission
): boolean {
  return userPermissions.includes(required);
}

export function hasAnyPermission(
  userPermissions: string[],
  required: Permission[]
): boolean {
  return required.some((p) => userPermissions.includes(p));
}

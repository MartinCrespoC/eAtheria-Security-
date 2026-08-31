/**
 * Infrastructure Module — Barrel Export
 *
 * Centralizes all infrastructure-related exports:
 * - Database (Prisma singleton, reset, adapter, setup)
 * - System configuration (key-value store)
 * - Mail (SMTP transport)
 * - Feature flags (database-backed, cached)
 */

// Database — Prisma singleton
export { prisma, resetPrismaClient } from "./db";
export { default } from "./db";

// Database adapter — multi-DB connection abstraction
export {
  getPrisma,
  getDatabaseProvider,
  validateConnectionUrl,
  buildConnectionUrl,
  testConnection,
  healthCheck,
  isDatabaseInitialized,
} from "./db-adapter";
export type { DatabaseProvider, ConnectionTestResult } from "./db-adapter";

// Database setup — first-run configuration
export {
  updateSchemaProvider,
  generateClient,
  runMigrations,
  pushSchema,
  seedDatabase,
  validateConnection,
  updateEnvFile,
  initializeDatabase,
} from "./db-setup";

// System configuration
export {
  getSystemConfig,
  setSystemConfig,
  getAllSystemConfig,
} from "./system-config";

// Mail (SMTP)
export {
  sendMail,
  inviteUserEmail,
  analysisCompleteEmail,
  securityAlertEmail,
} from "./mail";

// Feature flags
export {
  FEATURES,
  isFeatureEnabled,
  setFeatureFlag,
  getAllFeatureFlags,
  invalidateCache,
} from "./feature-flags";
export type { FeatureFlag } from "./feature-flags";

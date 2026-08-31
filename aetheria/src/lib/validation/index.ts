/**
 * Validation Module — Barrel Export
 *
 * Centralizes all shared Zod validation schemas:
 * - Auth (login, register, password reset)
 * - API keys, scans, applications
 * - AI models & providers
 * - System config, user profiles, invites
 * - Companies, GitHub connections
 * - Pagination & ID validation
 */

export {
  loginSchema,
  registerSchema,
  passwordResetSchema,
  apiKeySchema,
  scanSchema,
  applicationSchema,
  aiModelSchema,
  aiProviderSchema,
  systemConfigSchema,
  userProfileSchema,
  userInviteSchema,
  companySchema,
  githubConnectionSchema,
  idSchema,
  paginationSchema,
} from "./schemas";

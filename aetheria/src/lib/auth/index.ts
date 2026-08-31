/**
 * Auth Module — Barrel Export
 *
 * Centralizes all authentication-related exports:
 * - NextAuth configuration (authOptions, auth, requireAuth, requireSystemAdmin)
 * - API key authentication (authenticateApiKey, hasScope)
 * - SRP zero-knowledge password protocol (client & server)
 * - TOTP two-factor authentication
 */

// NextAuth core
export { authOptions, auth, requireAuth, requireSystemAdmin } from "./auth";

// API key authentication
export { authenticateApiKey, hasScope } from "./api-auth";

// SRP client (zero-knowledge password)
export {
  srpGenerateRegistration,
  srpClientStep1,
  srpClientStep2,
  srpClientStep3,
} from "./srp-client";
export type { SRPEphemeral, SRPSession } from "./srp-client";

// SRP server
export { srpServerStep1, srpServerStep2 } from "./srp-server";

// TOTP 2FA
export {
  generate2FASecret,
  generateQRCode,
  verify2FAToken,
  generateBackupCodes,
} from "./totp";

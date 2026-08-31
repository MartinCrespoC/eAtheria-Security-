/**
 * Re-export proxy — actual implementation lives in ./auth/totp.ts
 */
export {
  generate2FASecret,
  generateQRCode,
  verify2FAToken,
  generateBackupCodes,
} from "./auth/totp";

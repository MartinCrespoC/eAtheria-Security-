/**
 * Re-export proxy — actual implementation lives in ./infrastructure/mail.ts
 */
export {
  sendMail,
  inviteUserEmail,
  analysisCompleteEmail,
  securityAlertEmail,
} from "./infrastructure/mail";

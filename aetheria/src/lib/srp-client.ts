/**
 * Re-export proxy — actual implementation lives in ./auth/srp-client.ts
 */
export {
  srpGenerateRegistration,
  srpClientStep1,
  srpClientStep2,
  srpClientStep3,
} from "./auth/srp-client";
export type { SRPEphemeral, SRPSession } from "./auth/srp-client";

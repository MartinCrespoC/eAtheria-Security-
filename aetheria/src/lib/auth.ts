/**
 * Re-export proxy — actual implementation lives in ./auth/auth.ts
 * This file exists to maintain backward compatibility with existing
 * imports of "@/lib/auth".
 */
export {
  authOptions,
  auth,
  requireAuth,
  requireSystemAdmin,
} from "./auth/auth";

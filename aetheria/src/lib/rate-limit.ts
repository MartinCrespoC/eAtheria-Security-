/**
 * Re-export proxy — actual implementation lives in ./security/rate-limit.ts
 */
export {
  rateLimit,
  rateLimitRedis,
  getClientIp,
} from "./security/rate-limit";
export type { RateLimitOptions, RateLimitResult } from "./security/rate-limit";

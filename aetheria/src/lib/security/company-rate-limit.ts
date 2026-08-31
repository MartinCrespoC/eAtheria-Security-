/**
 * Company Rate Limiting - Edge-safe module
 *
 * Pure in-memory rate limiting with NO Node.js-only imports (no prisma, no
 * crypto, no audit logger). This module is safe to import from the Next.js
 * Edge Runtime (middleware). Node-only tenant utilities live in tenant-guard.ts,
 * which re-exports these functions for backwards compatibility.
 */

interface CompanyRateLimitEntry {
  count: number;
  resetAt: number;
}

const companyRateLimitStore = new Map<string, CompanyRateLimitEntry>();

// Cleanup old entries every 5 minutes
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of companyRateLimitStore.entries()) {
      if (now > entry.resetAt + 300_000) {
        companyRateLimitStore.delete(key);
      }
    }
  }, 300_000);
}

/**
 * Check rate limit for a specific company on a specific endpoint.
 * Defaults to 60 requests per minute.
 */
export function checkCompanyRateLimit(
  companyId: string,
  endpoint: string
): { allowed: boolean; remaining: number } {
  return checkCompanyRateLimitWithMax(companyId, endpoint, 60);
}

/**
 * Check rate limit with a company-specific limit override.
 * This is used by middleware to pass CompanySettings.rateLimitPerMinute.
 */
export function checkCompanyRateLimitWithMax(
  companyId: string,
  endpoint: string,
  maxRequests: number
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const key = `${companyId}:${endpoint}`;
  const windowMs = 60_000;

  let entry = companyRateLimitStore.get(key);

  if (!entry || now > entry.resetAt) {
    entry = {
      count: 1,
      resetAt: now + windowMs,
    };
    companyRateLimitStore.set(key, entry);
    return {
      allowed: true,
      remaining: maxRequests - 1,
    };
  }

  entry.count++;

  if (entry.count > maxRequests) {
    return {
      allowed: false,
      remaining: 0,
    };
  }

  return {
    allowed: true,
    remaining: maxRequests - entry.count,
  };
}

/**
 * Reset company rate limits (admin utility).
 */
export function resetCompanyRateLimits(companyId: string): void {
  for (const key of companyRateLimitStore.keys()) {
    if (key.startsWith(`${companyId}:`)) {
      companyRateLimitStore.delete(key);
    }
  }
}

/**
 * Get rate limit stats for a company.
 */
export function getCompanyRateLimitStats(companyId: string): {
  activeEndpoints: number;
  totalRequests: number;
} {
  let activeEndpoints = 0;
  let totalRequests = 0;

  for (const [key, entry] of companyRateLimitStore.entries()) {
    if (key.startsWith(`${companyId}:`)) {
      activeEndpoints++;
      totalRequests += entry.count;
    }
  }

  return { activeEndpoints, totalRequests };
}

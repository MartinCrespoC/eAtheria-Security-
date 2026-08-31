/**
 * Advanced Rate Limiting System
 * Adaptive rate limiting per endpoint with different tiers
 */

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
  violations: number; // Track repeated violations for adaptive limiting
}

// Rate limit configurations per endpoint type
const RATE_LIMITS: Record<string, RateLimitConfig> = {
  // Authentication endpoints - strict limits
  "auth:login": { windowMs: 60_000, maxRequests: 5 }, // 5 attempts per minute
  "auth:register": { windowMs: 3600_000, maxRequests: 3 }, // 3 per hour
  "auth:password-reset": { windowMs: 3600_000, maxRequests: 3 }, // 3 per hour
  
  // API endpoints - moderate limits
  "api:scan": { windowMs: 60_000, maxRequests: 10 }, // 10 scans per minute
  "api:analysis": { windowMs: 60_000, maxRequests: 30 }, // 30 requests per minute
  "api:general": { windowMs: 60_000, maxRequests: 100 }, // 100 requests per minute
  
  // Admin endpoints - relaxed limits
  "api:admin": { windowMs: 60_000, maxRequests: 200 }, // 200 requests per minute
  
  // Public endpoints - very strict
  "public": { windowMs: 60_000, maxRequests: 20 }, // 20 requests per minute
};

// In-memory store (in production, use Redis)
const rateLimitStore = new Map<string, RateLimitEntry>();

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now > entry.resetAt + 300_000) { // 5 minutes after reset
      rateLimitStore.delete(key);
    }
  }
}, 300_000);

/**
 * Get rate limit configuration for a given endpoint
 */
function getRateLimitConfig(pathname: string): RateLimitConfig {
  if (pathname.startsWith("/api/auth/callback") || pathname.includes("/login")) {
    return RATE_LIMITS["auth:login"];
  }
  if (pathname.includes("/register")) {
    return RATE_LIMITS["auth:register"];
  }
  if (pathname.includes("/password")) {
    return RATE_LIMITS["auth:password-reset"];
  }
  if (pathname.includes("/scan")) {
    return RATE_LIMITS["api:scan"];
  }
  if (pathname.includes("/analyses") || pathname.includes("/analysis")) {
    return RATE_LIMITS["api:analysis"];
  }
  if (pathname.startsWith("/api/admin")) {
    return RATE_LIMITS["api:admin"];
  }
  if (pathname.startsWith("/api/")) {
    return RATE_LIMITS["api:general"];
  }
  return RATE_LIMITS["public"];
}

/**
 * Check if request should be rate limited
 * Returns { allowed: boolean, retryAfter?: number }
 */
export function checkRateLimit(
  ip: string,
  pathname: string
): { allowed: boolean; retryAfter?: number; remaining?: number } {
  const config = getRateLimitConfig(pathname);
  const key = `${ip}:${pathname}`;
  const now = Date.now();
  
  let entry = rateLimitStore.get(key);
  
  // Create new entry if doesn't exist or window expired
  if (!entry || now > entry.resetAt) {
    entry = {
      count: 1,
      resetAt: now + config.windowMs,
      violations: entry?.violations || 0,
    };
    rateLimitStore.set(key, entry);
    
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
    };
  }
  
  // Increment count
  entry.count++;
  
  // Check if limit exceeded
  if (entry.count > config.maxRequests) {
    // Adaptive limiting: increase violations counter
    entry.violations++;
    
    // If repeated violations, extend the ban
    const penaltyMultiplier = Math.min(entry.violations, 10);
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000) * penaltyMultiplier;
    
    return {
      allowed: false,
      retryAfter,
    };
  }
  
  return {
    allowed: true,
    remaining: config.maxRequests - entry.count,
  };
}

/**
 * Reset rate limit for a specific IP (admin function)
 */
export function resetRateLimit(ip: string, pathname?: string): void {
  if (pathname) {
    const key = `${ip}:${pathname}`;
    rateLimitStore.delete(key);
  } else {
    // Reset all for this IP
    for (const key of rateLimitStore.keys()) {
      if (key.startsWith(`${ip}:`)) {
        rateLimitStore.delete(key);
      }
    }
  }
}

/**
 * Get rate limit stats for monitoring
 */
export function getRateLimitStats(): {
  totalKeys: number;
  topOffenders: Array<{ ip: string; violations: number }>;
} {
  const stats = new Map<string, number>();
  
  for (const [key, entry] of rateLimitStore.entries()) {
    const ip = key.split(":")[0];
    stats.set(ip, (stats.get(ip) || 0) + entry.violations);
  }
  
  const topOffenders = Array.from(stats.entries())
    .map(([ip, violations]) => ({ ip, violations }))
    .sort((a, b) => b.violations - a.violations)
    .slice(0, 10);
  
  return {
    totalKeys: rateLimitStore.size,
    topOffenders,
  };
}

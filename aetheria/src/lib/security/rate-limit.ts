import Redis from "ioredis";

// Redis client (lazy initialized)
let redis: Redis | null = null;

function getRedis(): Redis | null {
  if (redis) return redis;
  const url = process.env.REDIS_URL;
  if (!url) return null;
  try {
    redis = new Redis(url, {
      maxRetriesPerRequest: 1,
      connectTimeout: 3000,
      lazyConnect: true,
    });
    redis.connect().catch(() => {
      console.warn("[RATE-LIMIT] Redis connection failed, using in-memory fallback");
      redis = null;
    });
    return redis;
  } catch {
    return null;
  }
}

// In-memory fallback
const memoryStore = new Map<string, { count: number; resetAt: number }>();

export interface RateLimitOptions {
  maxRequests: number;
  windowMs: number;
}

export interface RateLimitResult {
  success: boolean;
  remaining: number;
  resetIn: number;
}

export async function rateLimitRedis(
  identifier: string,
  options: RateLimitOptions = { maxRequests: 10, windowMs: 60_000 }
): Promise<RateLimitResult> {
  const client = getRedis();
  if (client) {
    try {
      return await redisRateLimit(client, identifier, options);
    } catch {
      // Fallback to memory on Redis error
    }
  }
  return memoryRateLimit(identifier, options);
}

async function redisRateLimit(
  client: Redis,
  identifier: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const key = `rl:${identifier}`;
  const windowSec = Math.ceil(options.windowMs / 1000);

  const count = await client.incr(key);
  if (count === 1) {
    await client.expire(key, windowSec);
  }

  const ttl = await client.ttl(key);
  const resetIn = ttl > 0 ? ttl * 1000 : options.windowMs;

  if (count > options.maxRequests) {
    return { success: false, remaining: 0, resetIn };
  }

  return {
    success: true,
    remaining: options.maxRequests - count,
    resetIn,
  };
}

export function rateLimit(
  identifier: string,
  options: RateLimitOptions = { maxRequests: 10, windowMs: 60_000 }
): RateLimitResult {
  return memoryRateLimit(identifier, options);
}

function memoryRateLimit(
  identifier: string,
  options: RateLimitOptions
): RateLimitResult {
  const now = Date.now();
  const record = memoryStore.get(identifier);

  if (!record || record.resetAt < now) {
    memoryStore.set(identifier, {
      count: 1,
      resetAt: now + options.windowMs,
    });
    return {
      success: true,
      remaining: options.maxRequests - 1,
      resetIn: options.windowMs,
    };
  }

  if (record.count >= options.maxRequests) {
    return {
      success: false,
      remaining: 0,
      resetIn: record.resetAt - now,
    };
  }

  record.count += 1;
  return {
    success: true,
    remaining: options.maxRequests - record.count,
    resetIn: record.resetAt - now,
  };
}

// Cleanup old in-memory records periodically
if (typeof window === "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, value] of memoryStore.entries()) {
      if (value.resetAt < now) memoryStore.delete(key);
    }
  }, 60_000);
}

export function getClientIp(headers: Headers): string {
  return (
    headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    headers.get("x-real-ip") ||
    "unknown"
  );
}

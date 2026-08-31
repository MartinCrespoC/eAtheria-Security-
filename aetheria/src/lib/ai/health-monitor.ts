/**
 * AI Health Monitor
 * Tracks provider availability and latency through periodic health checks.
 * Uses the existing adapter testConnection() to verify API reachability
 * without consuming tokens.
 */

import { prisma } from "@/lib/db";
import { decrypt } from "./encryption";
import { getEnvApiKey } from "./env-keys";
import { getAdapter } from "./registry";
import type { AIProviderConfig } from "./providers/base";

export type HealthStatus = "healthy" | "degraded" | "down";

export interface HealthCheckResult {
  providerId: string;
  status: HealthStatus;
  latencyMs: number;
  error: string | null;
  checkedAt: Date;
}

export interface ProviderStatus {
  providerId: string;
  status: HealthStatus;
  latencyMs: number;
  error: string | null;
  lastCheckedAt: Date | null;
}

const DEGRADED_THRESHOLD_MS = 5000;
const RETENTION_DAYS = 7;

// In-memory cache: providerId → latest status (TTL 60s)
const statusCache = new Map<string, { result: HealthCheckResult; expiresAt: number }>();
const CACHE_TTL_MS = 60_000;

/**
 * Build an AIProviderConfig from a provider DB record (decrypt API key).
 */
async function buildProviderConfig(provider: {
  id: string;
  slug: string;
  type: string;
  baseUrl: string | null;
  apiKeyEnc: string | null;
  authType: string;
  config: unknown;
}): Promise<AIProviderConfig> {
  let apiKey = "";

  if (provider.apiKeyEnc) {
    apiKey = decrypt(provider.apiKeyEnc);
  } else if (provider.authType === "oauth") {
    const cfg = provider.config as Record<string, unknown> | null;
    if (cfg?.accessToken) {
      apiKey = decrypt(cfg.accessToken as string);
    }
  }

  if (!apiKey) {
    apiKey = getEnvApiKey(provider.slug);
  }

  return {
    apiKey,
    baseUrl: provider.baseUrl || undefined,
    config: (provider.config as Record<string, unknown>) || undefined,
  };
}

/**
 * Check a single provider's health by sending a lightweight testConnection request.
 * Stores the result in the AIHealthCheck table and updates the in-memory cache.
 * Never throws — errors are recorded as "down" status.
 */
export async function checkProviderHealth(providerId: string): Promise<HealthCheckResult> {
  let result: HealthCheckResult;

  try {
    const provider = await prisma.aIProvider.findUnique({
      where: { id: providerId },
    });

    if (!provider) {
      result = {
        providerId,
        status: "down",
        latencyMs: 0,
        error: "Provider not found",
        checkedAt: new Date(),
      };
    } else if (!provider.apiKeyEnc && provider.authType === "api_key" && !getEnvApiKey(provider.slug)) {
      result = {
        providerId,
        status: "down",
        latencyMs: 0,
        error: "No API key configured",
        checkedAt: new Date(),
      };
    } else {
      const adapter = getAdapter(provider.type, provider.slug);
      const config = await buildProviderConfig(provider);

      const start = Date.now();
      const testResult = await adapter.testConnection(config);
      const latencyMs = Date.now() - start;

      if (testResult.ok) {
        result = {
          providerId,
          status: latencyMs >= DEGRADED_THRESHOLD_MS ? "degraded" : "healthy",
          latencyMs,
          error: null,
          checkedAt: new Date(),
        };
      } else {
        result = {
          providerId,
          status: "down",
          latencyMs,
          error: testResult.error || "Connection failed",
          checkedAt: new Date(),
        };
      }
    }
  } catch (err) {
    result = {
      providerId,
      status: "down",
      latencyMs: 0,
      error: err instanceof Error ? err.message : "Unknown error during health check",
      checkedAt: new Date(),
    };
  }

  // Persist result (best-effort — don't let DB errors crash the monitor)
  try {
    await prisma.aIHealthCheck.create({
      data: {
        providerId,
        status: result.status,
        latencyMs: result.latencyMs,
        error: result.error,
      },
    });
  } catch (dbErr) {
    console.error("[health-monitor] Failed to persist health check:", dbErr);
  }

  // Update cache
  statusCache.set(providerId, {
    result,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return result;
}

/**
 * Run health checks for all active providers concurrently.
 * Returns a summary of results.
 */
export async function checkAllProviders(): Promise<{
  total: number;
  healthy: number;
  degraded: number;
  down: number;
  results: HealthCheckResult[];
}> {
  const providers = await prisma.aIProvider.findMany({
    where: { isActive: true },
    select: { id: true },
  });

  const results = await Promise.all(
    providers.map((p) => checkProviderHealth(p.id))
  );

  // Clean old records in the background (don't await)
  cleanupOldRecords().catch((err) =>
    console.error("[health-monitor] Cleanup failed:", err)
  );

  const summary = {
    total: results.length,
    healthy: results.filter((r) => r.status === "healthy").length,
    degraded: results.filter((r) => r.status === "degraded").length,
    down: results.filter((r) => r.status === "down").length,
    results,
  };

  return summary;
}

/**
 * Get the latest health status for a provider.
 * Uses the in-memory cache first (60s TTL), falls back to DB.
 */
export async function getProviderStatus(providerId: string): Promise<ProviderStatus> {
  // Check cache
  const cached = statusCache.get(providerId);
  if (cached && cached.expiresAt > Date.now()) {
    return {
      providerId,
      status: cached.result.status,
      latencyMs: cached.result.latencyMs,
      error: cached.result.error,
      lastCheckedAt: cached.result.checkedAt,
    };
  }

  // Fall back to DB
  const latest = await prisma.aIHealthCheck.findFirst({
    where: { providerId },
    orderBy: { checkedAt: "desc" },
  });

  if (!latest) {
    return {
      providerId,
      status: "down",
      latencyMs: 0,
      error: "No health check recorded",
      lastCheckedAt: null,
    };
  }

  return {
    providerId,
    status: latest.status as HealthStatus,
    latencyMs: latest.latencyMs,
    error: latest.error,
    lastCheckedAt: latest.checkedAt,
  };
}

/**
 * Get health check history for a provider within a time window.
 * @param providerId Provider ID
 * @param hours Number of hours of history to retrieve (default 24)
 */
export async function getHealthHistory(
  providerId: string,
  hours = 24
): Promise<Array<{
  id: string;
  status: HealthStatus;
  latencyMs: number;
  error: string | null;
  checkedAt: Date;
}>> {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const records = await prisma.aIHealthCheck.findMany({
    where: {
      providerId,
      checkedAt: { gte: since },
    },
    orderBy: { checkedAt: "asc" },
    take: 500, // Cap to prevent huge payloads
  });

  return records.map((r) => ({
    id: r.id,
    status: r.status as HealthStatus,
    latencyMs: r.latencyMs,
    error: r.error,
    checkedAt: r.checkedAt,
  }));
}

/**
 * Quick boolean check: is the provider currently healthy?
 * Uses cached status when available.
 */
export async function isProviderHealthy(providerId: string): Promise<boolean> {
  const status = await getProviderStatus(providerId);
  return status.status === "healthy";
}

/**
 * Compute uptime percentage for a provider over a given period.
 */
export async function getProviderUptime(
  providerId: string,
  hours = 24
): Promise<number> {
  const history = await getHealthHistory(providerId, hours);
  if (history.length === 0) return 0;

  const healthyCount = history.filter((h) => h.status !== "down").length;
  return (healthyCount / history.length) * 100;
}

/**
 * Delete health check records older than the retention window.
 */
async function cleanupOldRecords(): Promise<void> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000);
  await prisma.aIHealthCheck.deleteMany({
    where: { checkedAt: { lt: cutoff } },
  });
}

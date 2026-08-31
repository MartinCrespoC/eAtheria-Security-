/**
 * Feature Flags System
 *
 * Provides a centralized, database-backed feature flag mechanism.
 * Flags are cached in-memory with a 5-minute TTL to minimize DB lookups.
 * All flags default to ENABLED so nothing breaks when the system is first deployed.
 */

import { getSystemConfig, setSystemConfig } from "./system-config";

// ==================== FLAG DEFINITIONS ====================

export const FEATURES = {
  GITHUB_INTEGRATION: "feature_github_integration",
  GITLAB_INTEGRATION: "feature_gitlab_integration",
  AI_PENTESTING: "feature_ai_pentesting",
  AI_AUTO_FIX: "feature_ai_auto_fix",
  DAST_SCANNING: "feature_dast_scanning",
  SCA_SCANNING: "feature_sca_scanning",
  NOTIFICATIONS_EMAIL: "feature_notifications_email",
  NOTIFICATIONS_WEBHOOK: "feature_notifications_webhook",
  COMPANY_CUSTOM_BRANDING: "feature_company_custom_branding",
  QUEUE_REDIS: "feature_queue_redis",
} as const;

export type FeatureFlag = (typeof FEATURES)[keyof typeof FEATURES];

// ==================== CACHE ====================

let flagCache: Map<string, boolean> = new Map();
let lastRefresh = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// ==================== PUBLIC API ====================

/**
 * Check whether a feature flag is enabled.
 *
 * Resolution order:
 * 1. In-memory cache (if fresh)
 * 2. SystemConfig DB lookup
 * 3. Default: true (all features enabled by default)
 */
export async function isFeatureEnabled(flag: FeatureFlag): Promise<boolean> {
  // Refresh cache if stale
  if (Date.now() - lastRefresh > CACHE_TTL) {
    await refreshCache();
  }

  // Check cache
  const cached = flagCache.get(flag);
  if (cached !== undefined) {
    return cached;
  }

  // Fallback to DB lookup
  try {
    const value = await getSystemConfig<boolean>(flag, true);
    return value ?? true;
  } catch {
    // If DB lookup fails, default to enabled
    return true;
  }
}

/**
 * Enable or disable a feature flag.
 * Persists to SystemConfig and invalidates the cache.
 */
export async function setFeatureFlag(
  flag: FeatureFlag,
  enabled: boolean
): Promise<void> {
  await setSystemConfig(flag, enabled);
  flagCache.set(flag, enabled);
}

/**
 * Return all feature flags with their current status.
 */
export async function getAllFeatureFlags(): Promise<
  Record<string, { enabled: boolean; key: string; label: string }>
> {
  // Refresh cache if stale
  if (Date.now() - lastRefresh > CACHE_TTL) {
    await refreshCache();
  }

  const result: Record<string, { enabled: boolean; key: string; label: string }> = {};

  for (const [label, key] of Object.entries(FEATURES)) {
    const cached = flagCache.get(key);
    result[label] = {
      key,
      label: labelToHumanReadable(label),
      enabled: cached ?? true,
    };
  }

  return result;
}

/**
 * Clear the in-memory cache to force a refresh on next access.
 */
export function invalidateCache(): void {
  flagCache.clear();
  lastRefresh = 0;
}

// ==================== INTERNAL HELPERS ====================

async function refreshCache(): Promise<void> {
  try {
    const allConfig = await getSystemConfig<Record<string, boolean>>(
      "feature_flags_cache",
      undefined
    );

    // If we have a bulk cache key, use it
    if (allConfig && typeof allConfig === "object") {
      flagCache = new Map(Object.entries(allConfig));
    } else {
      // Otherwise, fetch each flag individually (only non-default ones are in DB)
      // We don't fetch all flags here to avoid N queries.
      // Individual flags will be fetched on-demand via isFeatureEnabled.
    }

    lastRefresh = Date.now();
  } catch {
    // If refresh fails, keep existing cache
    lastRefresh = Date.now();
  }
}

function labelToHumanReadable(label: string): string {
  return label
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

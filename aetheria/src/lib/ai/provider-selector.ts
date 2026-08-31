/**
 * AI Provider Selector
 * Resolves the best available AI provider for a company, handling
 * fallbacks, health status, and usage quotas.
 */

import { prisma } from "@/lib/db";
import { getProviderStatus, isProviderHealthy } from "./health-monitor";

export class AIProviderUnavailableError extends Error {
  constructor(message = "No healthy AI provider available") {
    super(message);
    this.name = "AIProviderUnavailableError";
  }
}

export interface SelectedProvider {
  id: string;
  slug: string;
  name: string;
  type: string;
  baseUrl: string | null;
  apiKeyEnc: string | null;
  authType: string;
  config: unknown;
  isFallback: boolean;
}

export interface QuotaStatus {
  allowed: boolean;
  remaining: number;
  percentUsed: number;
  tokenLimit: number | null;
  tokensUsed: number;
  costLimit: number | null;
  costUsed: number;
  blocked: boolean;
}

// Cache: companyId → { providerId, expiresAt }
const providerCache = new Map<string, { providerId: string; expiresAt: number }>();
const PROVIDER_CACHE_TTL_MS = 30_000; // 30s

/**
 * Select the best available AI provider for a company.
 *
 * Resolution order:
 * 1. Company's assigned provider (Company.aiProviderId)
 * 2. If unhealthy → fallbackProviderId on the assigned provider
 * 3. If fallback also unhealthy → first healthy active provider
 * 4. If ALL down → throw AIProviderUnavailableError
 */
export async function selectProvider(
  companyId: string,
  _taskType?: string
): Promise<SelectedProvider> {
  // 1. Get company's assigned provider
  const company = await prisma.company.findUnique({
    where: { id: companyId },
    include: { aiProvider: true },
  });

  if (!company) {
    throw new AIProviderUnavailableError("Company not found");
  }

  // 2. Check assigned provider health
  if (company.aiProvider && company.aiProvider.isActive) {
    const healthy = await isProviderHealthy(company.aiProvider.id);
    if (healthy) {
      providerCache.set(companyId, {
        providerId: company.aiProvider.id,
        expiresAt: Date.now() + PROVIDER_CACHE_TTL_MS,
      });
      return toSelectedProvider(company.aiProvider, false);
    }

    // 3. Check fallback provider
    if (company.aiProvider.fallbackProviderId) {
      const fallback = await prisma.aIProvider.findUnique({
        where: { id: company.aiProvider.fallbackProviderId },
      });

      if (fallback && fallback.isActive) {
        const fallbackHealthy = await isProviderHealthy(fallback.id);
        if (fallbackHealthy) {
          providerCache.set(companyId, {
            providerId: fallback.id,
            expiresAt: Date.now() + PROVIDER_CACHE_TTL_MS,
          });
          return toSelectedProvider(fallback, true);
        }
      }
    }
  }

  // 4. Fallback to first healthy active provider.
  //    Company-owned providers are private: only system providers
  //    (companyId null) or this company's own providers may serve it.
  const activeProviders = await prisma.aIProvider.findMany({
    where: {
      isActive: true,
      OR: [{ companyId: null }, { companyId }],
    },
  });

  for (const provider of activeProviders) {
    const healthy = await isProviderHealthy(provider.id);
    if (healthy) {
      providerCache.set(companyId, {
        providerId: provider.id,
        expiresAt: Date.now() + PROVIDER_CACHE_TTL_MS,
      });
      return toSelectedProvider(provider, true);
    }
  }

  // 5. All down
  throw new AIProviderUnavailableError(
    "All AI providers are unhealthy. Please check provider configuration and health status."
  );
}

/**
 * Check whether a company has remaining token/cost quota.
 */
export async function checkQuota(companyId: string): Promise<QuotaStatus> {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  const company = await prisma.company.findUnique({
    where: { id: companyId },
    select: { aiTokenLimit: true, aiCostLimit: true },
  });

  if (!company) {
    return {
      allowed: false,
      remaining: 0,
      percentUsed: 100,
      tokenLimit: null,
      tokensUsed: 0,
      costLimit: null,
      costUsed: 0,
      blocked: true,
    };
  }

  // Aggregate usage for this month
  const usage = await prisma.tokenUsage.aggregate({
    where: {
      companyId,
      date: { gte: monthStart },
    },
    _sum: {
      inputTokens: true,
      outputTokens: true,
      totalCost: true,
    },
  });

  const tokensUsed =
    Number(usage._sum.inputTokens || 0) + Number(usage._sum.outputTokens || 0);
  const costUsed = Number(usage._sum.totalCost || 0);

  const tokenLimit = company.aiTokenLimit;
  const costLimit = company.aiCostLimit ? Number(company.aiCostLimit) : null;

  let tokenPercent = 0;
  let costPercent = 0;

  if (tokenLimit && tokenLimit > 0) {
    tokenPercent = (tokensUsed / tokenLimit) * 100;
  }
  if (costLimit && costLimit > 0) {
    costPercent = (costUsed / costLimit) * 100;
  }

  const percentUsed = Math.max(tokenPercent, costPercent);
  const tokenBlocked = tokenLimit !== null && tokenLimit > 0 && tokensUsed >= tokenLimit;
  const costBlocked = costLimit !== null && costLimit > 0 && costUsed >= costLimit;
  const blocked = tokenBlocked || costBlocked;

  const remaining = tokenLimit
    ? Math.max(0, tokenLimit - tokensUsed)
    : Number.MAX_SAFE_INTEGER;

  return {
    allowed: !blocked,
    remaining,
    percentUsed: Math.min(100, percentUsed),
    tokenLimit,
    tokensUsed,
    costLimit,
    costUsed,
    blocked,
  };
}

/**
 * Track token usage for a company and provider.
 * Enqueues a notification if usage exceeds 80% of the limit.
 */
export async function trackUsage(
  companyId: string,
  providerId: string,
  inputTokens: number,
  outputTokens: number,
  cost: number
): Promise<void> {
  // Find a model for this provider to satisfy the TokenUsage FK
  const model = await prisma.aIModel.findFirst({
    where: { providerId },
    select: { id: true },
  });

  if (!model) {
    console.warn("[provider-selector] No model found for provider, skipping usage tracking:", providerId);
    return;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  // Upsert daily aggregated usage record
  const existing = await prisma.tokenUsage.findFirst({
    where: {
      date: today,
      modelId: model.id,
      companyId,
    },
  });

  if (existing) {
    await prisma.tokenUsage.update({
      where: { id: existing.id },
      data: {
        inputTokens: { increment: BigInt(inputTokens) },
        outputTokens: { increment: BigInt(outputTokens) },
        totalCost: { increment: cost },
      },
    });
  } else {
    await prisma.tokenUsage.create({
      data: {
        date: today,
        modelId: model.id,
        companyId,
        inputTokens: BigInt(inputTokens),
        outputTokens: BigInt(outputTokens),
        totalCost: cost,
      },
    });
  }

  // Check quota and notify if approaching limit (>80%)
  try {
    const quota = await checkQuota(companyId);
    if (quota.percentUsed >= 80 && quota.percentUsed < 100) {
      await enqueueLimitNotification(companyId, quota);
    }
  } catch (err) {
    console.error("[provider-selector] Quota check failed:", err);
  }
}

/**
 * Enqueue a notification to company admins about approaching AI usage limit.
 */
async function enqueueLimitNotification(
  companyId: string,
  quota: QuotaStatus
): Promise<void> {
  // Find company admins to notify
  const admins = await prisma.user.findMany({
    where: { companyId, isCompanyAdmin: true, isActive: true },
    select: { id: true },
  });

  if (admins.length === 0) return;

  const message =
    quota.blocked
      ? `AI usage limit reached (${quota.percentUsed.toFixed(0)}%). AI features are blocked until limits are increased.`
      : `AI usage is at ${quota.percentUsed.toFixed(0)}% of the monthly limit. Consider increasing limits soon.`;

  await prisma.notification.createMany({
    data: admins.map((admin) => ({
      userId: admin.id,
      companyId,
      title: "AI Usage Warning",
      message,
      type: "warning",
      metadata: {
        percentUsed: quota.percentUsed,
        tokensUsed: quota.tokensUsed,
        tokenLimit: quota.tokenLimit,
        costUsed: quota.costUsed,
        costLimit: quota.costLimit,
      } as never,
    })),
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function toSelectedProvider(
  provider: {
    id: string;
    slug: string;
    name: string;
    type: string;
    baseUrl: string | null;
    apiKeyEnc: string | null;
    authType: string;
    config: unknown;
  },
  isFallback: boolean
): SelectedProvider {
  return {
    id: provider.id,
    slug: provider.slug,
    name: provider.name,
    type: provider.type,
    baseUrl: provider.baseUrl,
    apiKeyEnc: provider.apiKeyEnc,
    authType: provider.authType,
    config: provider.config,
    isFallback,
  };
}

/**
 * Invalidate the provider cache for a company (e.g. after config change).
 */
export function invalidateProviderCache(companyId?: string): void {
  if (companyId) {
    providerCache.delete(companyId);
  } else {
    providerCache.clear();
  }
}

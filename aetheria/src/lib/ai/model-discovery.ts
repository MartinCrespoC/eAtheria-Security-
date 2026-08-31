/**
 * Model discovery: ask a provider (via its adapter) which models are
 * available for the configured key and upsert them into AIModel so the
 * analysis pipeline (and the UI pickers) can use them right away.
 */

import { prisma } from "@/lib/db";
import { getAdapter } from "./registry";

interface ProviderLike {
  id: string;
  slug: string;
  name: string;
  type: string;
  baseUrl: string | null;
  config: unknown;
}

export interface DiscoveredModel {
  id: string;
  name: string;
  modelId: string;
  isDefault: boolean;
}

export async function discoverAndUpsertModels(
  provider: ProviderLike,
  apiKey: string
): Promise<{ models: DiscoveredModel[]; error?: string }> {
  const adapter = getAdapter(provider.type, provider.slug);

  let available;
  try {
    available = await adapter.listModels({
      apiKey,
      baseUrl: provider.baseUrl || undefined,
      config: (provider.config as Record<string, unknown>) || undefined,
    });
  } catch (error) {
    return {
      models: [],
      error: error instanceof Error ? error.message : "No se pudieron listar los modelos",
    };
  }

  if (!available.length) {
    return { models: [], error: "El proveedor no devolvió modelos disponibles" };
  }

  const upserted: DiscoveredModel[] = [];

  for (const m of available) {
    const existing = await prisma.aIModel.findFirst({
      where: { providerId: provider.id, modelId: m.modelId },
    });

    if (existing) {
      await prisma.aIModel.update({
        where: { id: existing.id },
        data: { isActive: true },
      });
      upserted.push({ id: existing.id, name: existing.name, modelId: existing.modelId, isDefault: existing.isDefault });
      continue;
    }

    // AIModel.name is globally unique — disambiguate with the provider name
    // when the display name is already taken by another provider's model.
    let name = m.displayName || m.modelId;
    const nameTaken = await prisma.aIModel.findUnique({ where: { name } });
    if (nameTaken) {
      name = `${name} (${provider.name})`;
      const stillTaken = await prisma.aIModel.findUnique({ where: { name } });
      if (stillTaken) name = `${m.modelId} [${provider.slug}]`;
    }

    const created = await prisma.aIModel.create({
      data: {
        name,
        modelId: m.modelId,
        provider: provider.slug,
        providerId: provider.id,
        inputTokenCost: 0,
        outputTokenCost: 0,
        maxInputTokens: m.inputTokenLimit || 128000,
        maxOutputTokens: m.outputTokenLimit || 8192,
        isActive: true,
        isDefault: false,
      },
    });
    upserted.push({ id: created.id, name: created.name, modelId: created.modelId, isDefault: false });
  }

  return { models: upserted };
}

/**
 * Mark a model as the default. Scope: if the model belongs to a
 * company-owned provider, only demote models of that same provider so
 * company choices never disturb the global default.
 */
export async function setDefaultModel(modelId: string, providerId: string | null): Promise<void> {
  const model = await prisma.aIModel.findUnique({ where: { id: modelId } });
  if (!model) return;

  const provider = providerId
    ? await prisma.aIProvider.findUnique({ where: { id: providerId }, select: { companyId: true } })
    : null;

  await prisma.aIModel.updateMany({
    where: provider?.companyId
      ? { providerId, isDefault: true }
      : { isDefault: true },
    data: { isDefault: false },
  });
  await prisma.aIModel.update({ where: { id: model.id }, data: { isDefault: true } });
}

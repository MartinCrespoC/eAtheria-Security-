/**
 * Catalog-only seed — used by the Docker entrypoint on every container start.
 *
 * Seeds the *static* data the platform needs to run analyses out of the box:
 *   - System config defaults
 *   - AI providers + models (no API keys — those are set in the setup wizard)
 *   - License plans
 *   - CWE vulnerability catalog
 *
 * It deliberately does NOT create users, companies, or demo data — those are
 * configured interactively by the setup wizard on first launch.
 *
 * Idempotency: every record uses `update: {}` (create-if-missing only) so that
 * re-running on restart never overwrites changes made through the admin UI
 * (e.g. an API key or an edited license).
 */
import { PrismaClient } from "@prisma/client";
import { CWE_CATALOG } from "./seed-data/cwe-catalog";

const prisma = new PrismaClient();

async function main() {
  console.log("[SEED-CATALOG] Seeding static catalog data...");

  // ==================== SYSTEM CONFIG ====================
  const configs: { key: string; value: unknown }[] = [
    { key: "site_name", value: "AETHERIA" },
    { key: "site_tagline", value: "Personal AI Security Platform" },
    { key: "default_language", value: "es" },
    { key: "maintenance_mode", value: false },
    { key: "enforce_2fa_admins", value: false },
    { key: "max_file_size_mb", value: 1024 },
    { key: "rate_limit_enabled", value: true },
  ];
  for (const config of configs) {
    await prisma.systemConfig.upsert({
      where: { key: config.key },
      update: {},
      create: { key: config.key, value: config.value as never },
    });
  }

  // ==================== AI PROVIDERS ====================
  const aiProviders = [
    {
      slug: "gemini",
      name: "Google Gemini",
      type: "google-gemini",
      baseUrl: null,
      authType: "api_key",
      isActive: true,
    },
    {
      slug: "openai",
      name: "OpenAI",
      type: "openai-compatible",
      baseUrl: "https://api.openai.com/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "anthropic",
      name: "Anthropic",
      type: "anthropic",
      baseUrl: null,
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "openrouter",
      name: "OpenRouter",
      type: "openai-compatible",
      baseUrl: "https://openrouter.ai/api/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "deepseek",
      name: "DeepSeek",
      type: "openai-compatible",
      baseUrl: "https://api.deepseek.com",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "xai",
      name: "xAI / Grok",
      type: "openai-compatible",
      baseUrl: "https://api.x.ai/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "mistral",
      name: "Mistral AI",
      type: "openai-compatible",
      baseUrl: "https://api.mistral.ai/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "qwen",
      name: "Qwen / Alibaba",
      type: "openai-compatible",
      baseUrl: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "azure-openai",
      name: "Azure OpenAI",
      type: "azure-openai",
      baseUrl: null,
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "nvidia",
      name: "NVIDIA NIM (build.nvidia.com)",
      type: "openai-compatible",
      baseUrl: "https://integrate.api.nvidia.com/v1",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "perplexity",
      name: "Perplexity",
      type: "openai-compatible",
      baseUrl: "https://api.perplexity.ai",
      authType: "api_key",
      isActive: false,
    },
    {
      slug: "custom",
      name: "Custom Endpoint",
      type: "openai-compatible",
      baseUrl: null,
      authType: "api_key",
      isActive: false,
    },
  ];
  for (const provider of aiProviders) {
    await prisma.aIProvider.upsert({
      where: { slug: provider.slug },
      update: {},
      create: provider,
    });
  }

  // ==================== AI MODELS ====================
  // Models are NEVER seeded statically — they are discovered live from each
  // provider's API when an API key is saved (src/lib/ai/model-discovery.ts).
  // This keeps every provider (NVIDIA, Perplexity, OpenRouter, ...) in sync
  // with the models actually available for the configured key.

  // ==================== LICENSES ====================
  // Individual mode: no license plans — single personal instance, no billing.

  // ==================== CWE CATALOG ====================
  console.log(`[SEED-CATALOG] Creating ${CWE_CATALOG.length} CWE entries...`);
  for (const cwe of CWE_CATALOG) {
    await prisma.vulnerabilityCatalog.upsert({
      where: { cweId: cwe.cweId },
      update: {},
      create: {
        cweId: cwe.cweId,
        name: cwe.name,
        description: cwe.description,
        severity: cwe.severity,
        category: cwe.category,
        owaspTop10_2021: cwe.owaspTop10_2021 || null,
        owaspTop10_2017:
          (cwe as { owaspTop10_2017?: string }).owaspTop10_2017 || null,
        owaspAsvs: (cwe as { owaspAsvs?: string }).owaspAsvs || null,
        pciDss: (cwe as { pciDss?: string }).pciDss || null,
        languages: cwe.languages as never,
        remediation: cwe.remediation,
        references: cwe.references as never,
      },
    });
  }

  // ==================== INDIVIDUAL MODE: single company + admin ====================
  // Skip when SKIP_INDIVIDUAL=true (fresh install demo — wizard creates admin/company)
  if (process.env.SKIP_INDIVIDUAL !== "true") {
  const existingCompany = await prisma.company.findFirst({
    select: { id: true },
  });
  if (!existingCompany) {
    const defaultCompany = await prisma.company.create({
      data: {
        name: "Aetheria Individual",
        slug: "aetheria-individual",
        email: "admin@individual.local",
        isActive: true,
      },
    });
    console.log(
      `[SEED-CATALOG] Default company created: ${defaultCompany.slug}`,
    );

    const existingAdmin = await prisma.user.findFirst({
      where: { email: "admin@individual.local" },
      select: { id: true },
    });
    if (!existingAdmin) {
      const admin = await prisma.user.create({
        data: {
          email: "admin@individual.local",
          firstName: "Admin",
          lastName: "Individual",
          companyId: defaultCompany.id,
          isSystemAdmin: true,
          isCompanyAdmin: true,
          isActive: true,
          theme: "dark",
          preferredLanguage: "es",
        },
      });
      console.log(`[SEED-CATALOG] Default admin user created: ${admin.email}`);
    }
  }
  }

  console.log("[SEED-CATALOG] Catalog seeded successfully!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

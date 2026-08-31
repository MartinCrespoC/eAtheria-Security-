import { prisma } from "@/lib/db";

export async function getSystemConfig<T = unknown>(
  key: string,
  defaultValue?: T
): Promise<T | undefined> {
  try {
    const config = await prisma.systemConfig.findUnique({
      where: { key },
    });
    if (!config) return defaultValue;
    return config.value as T;
  } catch (error) {
    console.error(`Error fetching system config ${key}:`, error);
    return defaultValue;
  }
}

export async function setSystemConfig(key: string, value: unknown) {
  return prisma.systemConfig.upsert({
    where: { key },
    update: { value: value as never },
    create: { key, value: value as never },
  });
}

export async function getAllSystemConfig() {
  const configs = await prisma.systemConfig.findMany();
  const map: Record<string, unknown> = {};
  for (const config of configs) {
    map[config.key] = config.value;
  }
  return map;
}


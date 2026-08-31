/**
 * Re-export proxy — actual implementation lives in ./infrastructure/db.ts
 * This file exists to maintain backward compatibility with existing
 * imports of "@/lib/db" (25+ files reference it).
 */
export { prisma, resetPrismaClient } from "./infrastructure/db";
export { default } from "./infrastructure/db";

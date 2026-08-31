-- CreateTable
CREATE TABLE "ai_health_checks" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "latencyMs" INTEGER NOT NULL,
    "error" TEXT,
    "checkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_health_checks_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ai_health_checks_providerId_checkedAt_idx" ON "ai_health_checks"("providerId", "checkedAt");

-- AddForeignKey
ALTER TABLE "ai_health_checks" ADD CONSTRAINT "ai_health_checks_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "ai_providers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AlterTable: ai_providers
ALTER TABLE "ai_providers" ADD COLUMN "fallbackProviderId" TEXT;
ALTER TABLE "ai_providers" ADD COLUMN "maxTokensPerMonth" INTEGER;
ALTER TABLE "ai_providers" ADD COLUMN "costLimitPerMonth" DECIMAL(65,30);

-- AlterTable: companies
ALTER TABLE "companies" ADD COLUMN "aiTokenLimit" INTEGER;
ALTER TABLE "companies" ADD COLUMN "aiCostLimit" DECIMAL(65,30);

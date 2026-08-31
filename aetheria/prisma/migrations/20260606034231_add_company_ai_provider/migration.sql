-- AlterTable
ALTER TABLE "companies" ADD COLUMN     "aiProviderId" TEXT;

-- CreateIndex
CREATE INDEX "companies_aiProviderId_idx" ON "companies"("aiProviderId");

-- AddForeignKey
ALTER TABLE "companies" ADD CONSTRAINT "companies_aiProviderId_fkey" FOREIGN KEY ("aiProviderId") REFERENCES "ai_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Company-owned AI providers: each company can hold its own provider with
-- its own API key, independent from the global/system providers.

ALTER TABLE "ai_providers" ADD COLUMN "companyId" TEXT;

ALTER TABLE "ai_providers"
  ADD CONSTRAINT "ai_providers_companyId_fkey"
  FOREIGN KEY ("companyId") REFERENCES "companies"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

CREATE INDEX "ai_providers_companyId_idx" ON "ai_providers"("companyId");

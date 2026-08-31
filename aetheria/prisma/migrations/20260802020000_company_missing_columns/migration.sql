-- Reconcile drift: Company columns added to the schema via db push
-- (without migrations) that production databases are missing.
-- Idempotent guards make this safe on databases that already have them.

ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "address" TEXT;
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "licenseKey" TEXT;
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "aiCostLimit" DECIMAL(65,30);
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "customInputTokenCost" DECIMAL(65,30);
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "customOutputTokenCost" DECIMAL(65,30);
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "showInfoFindings" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "companies" ADD COLUMN IF NOT EXISTS "defaultScanLevel" TEXT NOT NULL DEFAULT 'STATIC';

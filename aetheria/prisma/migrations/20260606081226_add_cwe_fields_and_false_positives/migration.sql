-- AlterTable
ALTER TABLE "vulnerability_catalog" ADD COLUMN     "kevCount" INTEGER,
ADD COLUMN     "lastSyncedAt" TIMESTAMP(3),
ADD COLUMN     "rank" INTEGER,
ADD COLUMN     "source" TEXT,
ADD COLUMN     "year" INTEGER;

-- CreateTable
CREATE TABLE "false_positive_patterns" (
    "id" TEXT NOT NULL,
    "language" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "context" TEXT,
    "cweIds" JSONB NOT NULL,
    "examples" JSONB NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "false_positive_patterns_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "false_positive_patterns_language_idx" ON "false_positive_patterns"("language");

-- CreateIndex
CREATE INDEX "false_positive_patterns_isActive_idx" ON "false_positive_patterns"("isActive");

-- CreateIndex
CREATE INDEX "vulnerability_catalog_year_idx" ON "vulnerability_catalog"("year");

-- CreateIndex
CREATE INDEX "vulnerability_catalog_rank_idx" ON "vulnerability_catalog"("rank");

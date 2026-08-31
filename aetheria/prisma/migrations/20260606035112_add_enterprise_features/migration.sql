-- AlterTable
ALTER TABLE "companies" ADD COLUMN     "defaultLanguage" TEXT NOT NULL DEFAULT 'es',
ADD COLUMN     "portalSlogan" TEXT DEFAULT 'Enterprise Security Platform',
ADD COLUMN     "portalTitle" TEXT DEFAULT 'AETHERIA Security';

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "isCompanyAdmin" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "impersonation_logs" (
    "id" TEXT NOT NULL,
    "adminUserId" TEXT NOT NULL,
    "targetUserId" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "ipAddress" TEXT,
    "reason" TEXT,
    "actionsPerformed" JSONB,

    CONSTRAINT "impersonation_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "impersonation_logs_adminUserId_idx" ON "impersonation_logs"("adminUserId");

-- CreateIndex
CREATE INDEX "impersonation_logs_targetUserId_idx" ON "impersonation_logs"("targetUserId");

-- AddForeignKey
ALTER TABLE "impersonation_logs" ADD CONSTRAINT "impersonation_logs_adminUserId_fkey" FOREIGN KEY ("adminUserId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "impersonation_logs" ADD CONSTRAINT "impersonation_logs_targetUserId_fkey" FOREIGN KEY ("targetUserId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

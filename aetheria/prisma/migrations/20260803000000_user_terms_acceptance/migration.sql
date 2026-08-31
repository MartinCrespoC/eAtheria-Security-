-- AlterTable
ALTER TABLE "users"
ADD COLUMN "termsAcceptedAt" TIMESTAMP(3);
ALTER TABLE "users"
ADD COLUMN "termsAcceptedIp" TEXT;

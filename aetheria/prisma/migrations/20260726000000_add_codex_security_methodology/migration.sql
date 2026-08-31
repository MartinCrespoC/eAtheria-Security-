-- AlterTable: Add codex-security methodology fields to vulnerabilities
ALTER TABLE "vulnerabilities" ADD COLUMN "attackPathDataflow" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "attackPathReachability" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "severityRationale" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "severityChangeConditions" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "impactLevel" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "likelihoodLevel" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "validationMethod" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "validationEvidence" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "validationConfidence" DOUBLE PRECISION;
ALTER TABLE "vulnerabilities" ADD COLUMN "counterevidence" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "proofGaps" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "rootCauseSummary" TEXT;
ALTER TABLE "vulnerabilities" ADD COLUMN "codeEvidence" JSONB;
ALTER TABLE "vulnerabilities" ADD COLUMN "remediationTests" JSONB;
ALTER TABLE "vulnerabilities" ADD COLUMN "preventiveControls" JSONB;

-- CreateTable: threat_models
CREATE TABLE "threat_models" (
    "id" TEXT NOT NULL,
    "analysisId" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "actors" JSONB,
    "boundaries" JSONB,
    "assets" JSONB,
    "threats" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threat_models_pkey" PRIMARY KEY ("id")
);

-- CreateTable: triage_results
CREATE TABLE "triage_results" (
    "id" TEXT NOT NULL,
    "companyId" TEXT NOT NULL,
    "inputId" TEXT,
    "sourceType" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "verdict" TEXT NOT NULL,
    "confidence" TEXT,
    "exploitRank" INTEGER,
    "boundaryAssessment" JSONB,
    "evidence" TEXT,
    "counterevidence" TEXT,
    "proofGaps" TEXT,
    "affectedPaths" JSONB,
    "recommendedNext" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "triage_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable: hardening_proposals
CREATE TABLE "hardening_proposals" (
    "id" TEXT NOT NULL,
    "analysisId" TEXT,
    "companyId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "opportunityId" TEXT NOT NULL,
    "diagnosis" TEXT NOT NULL,
    "options" JSONB NOT NULL,
    "recommended" TEXT,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "hardening_proposals_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "threat_models_analysisId_key" ON "threat_models"("analysisId");

-- CreateIndex
CREATE INDEX "triage_results_companyId_idx" ON "triage_results"("companyId");
CREATE INDEX "triage_results_verdict_idx" ON "triage_results"("verdict");

-- CreateIndex
CREATE INDEX "hardening_proposals_companyId_idx" ON "hardening_proposals"("companyId");
CREATE INDEX "hardening_proposals_analysisId_idx" ON "hardening_proposals"("analysisId");

-- AddForeignKey
ALTER TABLE "threat_models" ADD CONSTRAINT "threat_models_analysisId_fkey" FOREIGN KEY ("analysisId") REFERENCES "analyses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "triage_results" ADD CONSTRAINT "triage_results_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "companies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "hardening_proposals" ADD CONSTRAINT "hardening_proposals_companyId_fkey" FOREIGN KEY ("companyId") REFERENCES "companies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

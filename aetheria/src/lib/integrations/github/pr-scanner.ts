import { prisma } from "@/lib/db";
import { enqueueScan } from "@/lib/queue";

/**
 * Trigger a security scan for a GitHub Pull Request.
 * Creates or reuses Application + AppVersion records, then enqueues the scan.
 */
export async function triggerPRScan(
  connectionId: string,
  prNumber: number,
  headSha: string,
  repoFullName: string,
  branch: string
): Promise<{ analysisId: string; jobId: string }> {
  // Fetch connection with company
  const connection = await prisma.githubConnection.findUnique({
    where: { id: connectionId },
    include: { company: { select: { id: true, slug: true } } },
  });

  if (!connection) {
    throw new Error(`GitHub connection ${connectionId} not found`);
  }

  const companyId = connection.companyId;

  // Get or create application for this repo
  const appSlug = repoFullName.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
  let application = await prisma.application.findFirst({
    where: { companyId, slug: appSlug },
  });

  if (!application) {
    application = await prisma.application.create({
      data: {
        name: repoFullName.split("/").pop() || repoFullName,
        slug: appSlug,
        repoUrl: `https://github.com/${repoFullName}`,
        companyId,
      },
    });
  }

  // Create version for this PR/SHA
  const versionTag = `pr-${prNumber}-${headSha.slice(0, 7)}`;
  let version = await prisma.appVersion.findFirst({
    where: { applicationId: application.id, version: versionTag },
  });

  if (!version) {
    version = await prisma.appVersion.create({
      data: {
        version: versionTag,
        branch,
        commitHash: headSha,
        sourceType: "GITHUB",
        sourceUrl: `https://github.com/${repoFullName}/tree/${headSha}`,
        applicationId: application.id,
      },
    });
  }

  // Create analysis record
  const analysis = await prisma.analysis.create({
    data: {
      appVersionId: version.id,
      scanTypes: ["SAST", "SCA"],
      aiValidation: true,
      status: "PENDING",
    },
  });

  // Enqueue the scan job
  const { jobId } = await enqueueScan({
    applicationId: application.id,
    versionId: version.id,
    companyId,
    scanTypes: ["sast", "sca"],
    source: "github",
    analysisId: analysis.id,
    metadata: {
      prNumber,
      headSha,
      branch,
      repoFullName,
      connectionId,
    },
  });

  return { analysisId: analysis.id, jobId };
}

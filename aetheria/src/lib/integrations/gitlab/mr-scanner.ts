import { prisma } from "@/lib/db";
import { enqueueScan } from "@/lib/queue";

/**
 * Trigger a security scan for a GitLab Merge Request.
 * Creates or reuses Application + AppVersion records, then enqueues the scan.
 */
export async function triggerMRScan(
  connectionId: string,
  mrIid: number,
  sourceBranch: string,
  projectId: string,
  sha?: string
): Promise<{ analysisId: string; jobId: string }> {
  // Fetch connection
  const connection = await prisma.gitlabConnection.findUnique({
    where: { id: connectionId },
    include: { company: { select: { id: true } } },
  });

  if (!connection) {
    throw new Error(`GitLab connection ${connectionId} not found`);
  }

  const companyId = connection.companyId;

  // Get or create application for this project
  const appSlug = projectId.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
  let application = await prisma.application.findFirst({
    where: { companyId, slug: appSlug },
  });

  if (!application) {
    application = await prisma.application.create({
      data: {
        name: connection.name || projectId,
        slug: appSlug,
        repoUrl: connection.projectUrl,
        companyId,
      },
    });
  }

  // Create version for this MR
  const versionTag = `mr-${mrIid}-${sha ? sha.slice(0, 7) : Date.now()}`;
  let version = await prisma.appVersion.findFirst({
    where: { applicationId: application.id, version: versionTag },
  });

  if (!version) {
    version = await prisma.appVersion.create({
      data: {
        version: versionTag,
        branch: sourceBranch,
        commitHash: sha,
        sourceType: "URL",
        sourceUrl: `${connection.projectUrl}/-/merge_requests/${mrIid}`,
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
    source: "gitlab",
    analysisId: analysis.id,
    metadata: {
      mrIid,
      headSha: sha,
      branch: sourceBranch,
      connectionId,
      projectId,
    },
  });

  return { analysisId: analysis.id, jobId };
}

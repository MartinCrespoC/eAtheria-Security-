import { prisma } from "@/lib/db";
import { triggerAnalysis } from "@/lib/analysis/trigger";
import { enqueueNotification } from "../notification-queue";
import { ScanJobData } from "../scan-queue";

export interface ScanJobResult {
  analysisId: string;
  status: "completed" | "failed";
  totalIssues: number;
  criticalCount: number;
  highCount: number;
}

/**
 * Process a scan job:
 * 1. Fetch or create Analysis record
 * 2. Run appropriate engines (SAST/SCA/DAST) via triggerAnalysis
 * 3. Update Analysis status
 * 4. Enqueue notification job
 */
export async function processScanJob(data: ScanJobData): Promise<ScanJobResult> {
  const { applicationId, versionId, companyId, scanTypes, analysisId, metadata } = data;

  let analysis;

  if (analysisId) {
    // Use existing analysis record
    analysis = await prisma.analysis.findUnique({
      where: { id: analysisId },
    });
    if (!analysis) {
      throw new Error(`Analysis ${analysisId} not found`);
    }
  } else {
    // Create new analysis record
    analysis = await prisma.analysis.create({
      data: {
        appVersionId: versionId,
        scanTypes: scanTypes.map((t) => t.toUpperCase()),
        aiValidation: true,
        status: "PENDING",
        triggeredBy: metadata?.triggeredBy,
      },
    });
  }

  try {
    // Store PR/MR context in analysis metadata (if available)
    if (metadata?.prNumber || metadata?.mrIid) {
      await prisma.analysis.update({
        where: { id: analysis.id },
        data: {
          // Store context as part of scanTypes JSON metadata
          scanTypes: {
            types: scanTypes.map((t) => t.toUpperCase()),
            source: data.source,
            prNumber: metadata.prNumber,
            mrIid: metadata.mrIid,
            headSha: metadata.headSha,
            branch: metadata.branch,
            repoFullName: metadata.repoFullName,
            connectionId: metadata.connectionId,
            projectId: metadata.projectId,
            platform: metadata.prNumber ? "github" : metadata.mrIid ? "gitlab" : undefined,
          },
        },
      });
    }

    // Run the analysis using existing engines
    await triggerAnalysis(analysis.id);

    // Fetch updated analysis with results
    const completedAnalysis = await prisma.analysis.findUnique({
      where: { id: analysis.id },
    });

    const result: ScanJobResult = {
      analysisId: analysis.id,
      status: completedAnalysis?.status === "COMPLETED" ? "completed" : "failed",
      totalIssues: completedAnalysis?.totalIssues || 0,
      criticalCount: completedAnalysis?.criticalCount || 0,
      highCount: completedAnalysis?.highCount || 0,
    };

    // Enqueue notification for completed scan
    await enqueueScanNotifications(data, result, applicationId);

    return result;
  } catch (error) {
    console.error(`Scan job failed for analysis ${analysis.id}:`, error);

    await prisma.analysis.update({
      where: { id: analysis.id },
      data: {
        status: "FAILED",
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        completedAt: new Date(),
      },
    }).catch(console.error);

    throw error;
  }
}

async function enqueueScanNotifications(
  data: ScanJobData,
  result: ScanJobResult,
  applicationId: string
) {
  try {
    // Get application details for notification
    const app = await prisma.application.findUnique({
      where: { id: applicationId },
      select: { name: true },
    });

    const appName = app?.name || "Unknown App";

    // In-app notification for the triggering user
    if (data.metadata?.triggeredBy) {
      await enqueueNotification({
        type: "in_app",
        userId: data.metadata.triggeredBy,
        companyId: data.companyId,
        payload: {
          title: `Scan Complete: ${appName}`,
          message: `Found ${result.totalIssues} issues (${result.criticalCount} critical, ${result.highCount} high)`,
          notificationType: "scan_complete",
          metadata: {
            analysisId: result.analysisId,
            totalIssues: result.totalIssues,
            criticalCount: result.criticalCount,
          },
        },
      });
    }

    // PR comment notification (GitHub)
    if (data.metadata?.prNumber && data.metadata?.connectionId && data.metadata?.repoFullName) {
      await enqueueNotification({
        type: "pr_comment",
        companyId: data.companyId,
        payload: {
          platform: "github",
          connectionId: data.metadata.connectionId,
          prNumber: data.metadata.prNumber,
          repoFullName: data.metadata.repoFullName,
          analysisId: result.analysisId,
        },
      });
    }

    // MR comment notification (GitLab)
    if (data.metadata?.mrIid && data.metadata?.connectionId && data.metadata?.projectId) {
      await enqueueNotification({
        type: "pr_comment",
        companyId: data.companyId,
        payload: {
          platform: "gitlab",
          connectionId: data.metadata.connectionId,
          mrIid: data.metadata.mrIid,
          projectId: data.metadata.projectId,
          analysisId: result.analysisId,
        },
      });
    }
  } catch (notifError) {
    // Notifications should not break the scan job
    console.error("Failed to enqueue scan notifications:", notifError);
  }
}

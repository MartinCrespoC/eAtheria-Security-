import { createQueue, isRedisAvailable } from "./redis";
import { prisma } from "@/lib/db";
import { Queue } from "bullmq";

export type ScanType = "sast" | "sca" | "dast";
export type ScanSource = "zip" | "github" | "gitlab" | "api";

export interface ScanJobData {
  applicationId: string;
  versionId: string;
  companyId: string;
  scanTypes: ScanType[];
  source: ScanSource;
  analysisId?: string;
  metadata?: {
    prNumber?: number;
    mrIid?: number;
    headSha?: string;
    branch?: string;
    repoFullName?: string;
    connectionId?: string;
    projectId?: string;
    triggeredBy?: string;
  };
}

let scanQueue: Queue<ScanJobData> | null = null;

function getScanQueue(): Queue<ScanJobData> | null {
  if (scanQueue) return scanQueue;
  scanQueue = createQueue<ScanJobData>("scan-jobs");
  return scanQueue;
}

/**
 * Enqueue a scan job. If Redis is available, uses BullMQ.
 * Falls back to DB-persisted job + direct execution if no Redis.
 */
export async function enqueueScan(data: ScanJobData): Promise<{ jobId: string }> {
  const queue = getScanQueue();

  if (queue && isRedisAvailable()) {
    const job = await queue.add("scan", data, {
      jobId: `scan-${data.versionId}-${Date.now()}`,
    });
    return { jobId: job.id || `scan-${data.versionId}-${Date.now()}` };
  }

  // Fallback: persist to DB and process inline
  const dbJob = await prisma.queueJob.create({
    data: {
      type: "scan",
      status: "pending",
      payload: JSON.parse(JSON.stringify(data)) as never,
      companyId: data.companyId,
    },
  });

  // Process asynchronously (fire-and-forget)
  processFallbackScan(dbJob.id, data).catch(console.error);

  return { jobId: dbJob.id };
}

async function processFallbackScan(jobId: string, data: ScanJobData) {
  await prisma.queueJob.update({
    where: { id: jobId },
    data: { status: "processing", attempts: { increment: 1 } },
  });

  try {
    // Dynamic import to avoid circular dependencies
    const { processScanJob } = await import("./workers/scan-worker");
    const result = await processScanJob(data);

    await prisma.queueJob.update({
      where: { id: jobId },
      data: {
        status: "completed",
        result: JSON.parse(JSON.stringify(result)) as never,
        completedAt: new Date(),
      },
    });
  } catch (error) {
    await prisma.queueJob.update({
      where: { id: jobId },
      data: {
        status: "failed",
        error: error instanceof Error ? error.message : "Unknown error",
      },
    });
  }
}

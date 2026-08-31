import { createQueue, isRedisAvailable } from "./redis";
import { prisma } from "@/lib/db";
import { Queue } from "bullmq";

export type NotificationType = "pr_comment" | "email" | "in_app" | "webhook_out" | "telegram" | "whatsapp";

export interface NotificationJobData {
  type: NotificationType;
  userId?: string;
  companyId: string;
  payload: {
    // pr_comment
    connectionId?: string;
    prNumber?: number;
    mrIid?: number;
    repoFullName?: string;
    projectId?: string;
    analysisId?: string;
    platform?: "github" | "gitlab";

    // email
    to?: string;
    subject?: string;
    htmlBody?: string;

    // in_app
    title?: string;
    message?: string;
    notificationType?: string;
    metadata?: Record<string, unknown>;

    // webhook_out
    webhookUrl?: string;
    webhookPayload?: Record<string, unknown>;

    // telegram / whatsapp
    chatId?: string;
    messagingConfig?: Record<string, unknown>;
  };
}

let notificationQueue: Queue<NotificationJobData> | null = null;

function getNotificationQueue(): Queue<NotificationJobData> | null {
  if (notificationQueue) return notificationQueue;
  notificationQueue = createQueue<NotificationJobData>("notification-jobs");
  return notificationQueue;
}

export async function enqueueNotification(data: NotificationJobData): Promise<{ jobId: string }> {
  const queue = getNotificationQueue();

  if (queue && isRedisAvailable()) {
    const job = await queue.add(data.type, data);
    return { jobId: job.id || `notif-${Date.now()}` };
  }

  // Fallback: persist to DB and process inline
  const dbJob = await prisma.queueJob.create({
    data: {
      type: "notification",
      status: "pending",
      payload: JSON.parse(JSON.stringify(data)) as never,
      companyId: data.companyId,
    },
  });

  processFallbackNotification(dbJob.id, data).catch(console.error);

  return { jobId: dbJob.id };
}

async function processFallbackNotification(jobId: string, data: NotificationJobData) {
  await prisma.queueJob.update({
    where: { id: jobId },
    data: { status: "processing", attempts: { increment: 1 } },
  });

  try {
    const { processNotificationJob } = await import("./workers/notification-worker");
    const result = await processNotificationJob(data);

    await prisma.queueJob.update({
      where: { id: jobId },
      data: {
        status: "completed",
        result: result as never,
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

import { prisma } from "@/lib/db";
import { sendMail } from "@/lib/mail";
import { NotificationJobData } from "../notification-queue";
import { sendMessagingNotification, type MessagingPlatform } from "@/lib/messaging";

export interface NotificationJobResult {
  type: string;
  success: boolean;
  message?: string;
}

/**
 * Process notification jobs:
 * - pr_comment: post to GitHub/GitLab PR/MR
 * - email: send via nodemailer
 * - in_app: create Notification record in DB
 * - webhook_out: POST to user-configured webhook URL
 */
export async function processNotificationJob(data: NotificationJobData): Promise<NotificationJobResult> {
  switch (data.type) {
    case "pr_comment":
      return handlePRComment(data);
    case "email":
      return handleEmail(data);
    case "in_app":
      return handleInApp(data);
    case "webhook_out":
      return handleWebhookOut(data);
    case "telegram":
      return handleMessaging(data, "telegram");
    case "whatsapp":
      return handleMessaging(data, "whatsapp");
    default:
      return { type: data.type, success: false, message: `Unknown notification type: ${data.type}` };
  }
}

async function handlePRComment(data: NotificationJobData): Promise<NotificationJobResult> {
  const { connectionId, prNumber, mrIid, repoFullName, projectId, analysisId, platform } = data.payload;

  if (!analysisId) {
    return { type: "pr_comment", success: false, message: "Missing analysisId" };
  }

  try {
    if (platform === "github" && connectionId && prNumber && repoFullName) {
      const { postScanResults: postGithubResults } = await import("@/lib/integrations/github/pr-commenter");
      await postGithubResults(connectionId, prNumber, repoFullName, analysisId);
      return { type: "pr_comment", success: true, message: "Posted GitHub PR comment" };
    }

    if (platform === "gitlab" && connectionId && mrIid && projectId) {
      const { postScanResults: postGitlabResults } = await import("@/lib/integrations/gitlab/mr-commenter");
      await postGitlabResults(connectionId, mrIid, projectId, analysisId);
      return { type: "pr_comment", success: true, message: "Posted GitLab MR comment" };
    }

    return { type: "pr_comment", success: false, message: "Missing required PR/MR context" };
  } catch (error) {
    console.error("PR comment notification failed:", error);
    return { type: "pr_comment", success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

async function handleEmail(data: NotificationJobData): Promise<NotificationJobResult> {
  const { to, subject, htmlBody } = data.payload;

  if (!to || !subject || !htmlBody) {
    return { type: "email", success: false, message: "Missing email fields (to, subject, htmlBody)" };
  }

  try {
    const result = await sendMail({ to, subject, html: htmlBody });
    return { type: "email", success: result.success !== false, message: result.success ? "Email sent" : "SMTP not configured" };
  } catch (error) {
    console.error("Email notification failed:", error);
    return { type: "email", success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

async function handleInApp(data: NotificationJobData): Promise<NotificationJobResult> {
  const { title, message, notificationType, metadata } = data.payload;

  if (!data.userId || !title || !message) {
    return { type: "in_app", success: false, message: "Missing userId, title, or message" };
  }

  try {
    await prisma.notification.create({
      data: {
        userId: data.userId,
        companyId: data.companyId,
        type: notificationType || "info",
        title,
        message,
        metadata: (metadata || undefined) as never,
      },
    });

    return { type: "in_app", success: true, message: "In-app notification created" };
  } catch (error) {
    console.error("In-app notification failed:", error);
    return { type: "in_app", success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

async function handleWebhookOut(data: NotificationJobData): Promise<NotificationJobResult> {
  const { webhookUrl, webhookPayload } = data.payload;

  if (!webhookUrl) {
    return { type: "webhook_out", success: false, message: "Missing webhookUrl" };
  }

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(webhookPayload || { event: "scan_complete", companyId: data.companyId }),
      signal: AbortSignal.timeout(10000), // 10s timeout
    });

    if (!response.ok) {
      return { type: "webhook_out", success: false, message: `Webhook returned ${response.status}` };
    }

    return { type: "webhook_out", success: true, message: "Webhook delivered" };
  } catch (error) {
    console.error("Webhook notification failed:", error);
    return { type: "webhook_out", success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

async function handleMessaging(data: NotificationJobData, platform: MessagingPlatform): Promise<NotificationJobResult> {
  const { chatId, messagingConfig, message, title } = data.payload;

  if (!chatId) {
    return { type: platform, success: false, message: "Missing chatId" };
  }

  if (!messagingConfig) {
    return { type: platform, success: false, message: "Missing messaging configuration" };
  }

  const text = message || title || "Notificación de EATHERIA";

  try {
    const result = await sendMessagingNotification(platform, messagingConfig, chatId, text);

    if (!result.success) {
      return { type: platform, success: false, message: result.error || "Send failed" };
    }

    return { type: platform, success: true, message: `Message sent via ${platform} (ID: ${result.messageId || "N/A"})` };
  } catch (error) {
    console.error(`${platform} notification failed:`, error);
    return { type: platform, success: false, message: error instanceof Error ? error.message : "Unknown error" };
  }
}

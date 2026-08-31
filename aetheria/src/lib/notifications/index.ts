import { createInAppNotification } from "./in-app";
import { sendNotificationEmail } from "./email";
import { enqueueNotification } from "@/lib/queue/notification-queue";

export interface SendNotificationOptions {
  userId: string;
  companyId: string;
  type: string; // scan_complete, vuln_found, pr_scanned, info, warning, error
  title: string;
  message: string;
  metadata?: Record<string, unknown>;
  channels?: ("in_app" | "email" | "telegram" | "whatsapp")[];
  // Messaging-specific
  chatId?: string;
  messagingConfig?: Record<string, unknown>;
}

/**
 * Send a notification to a user via the specified channels.
 * Defaults to in_app if no channels specified.
 */
export async function sendNotification(options: SendNotificationOptions): Promise<void> {
  const channels = options.channels || ["in_app"];

  const tasks = channels.map(async (channel) => {
    switch (channel) {
      case "in_app":
        return createInAppNotification(
          options.userId,
          options.companyId,
          options.type,
          options.title,
          options.message,
          options.metadata
        );
      case "email":
        return sendNotificationEmail(
          options.userId,
          options.title,
          options.message
        );
      case "telegram":
        return enqueueNotification({
          type: "telegram",
          userId: options.userId,
          companyId: options.companyId,
          payload: {
            chatId: options.chatId,
            messagingConfig: options.messagingConfig,
            title: options.title,
            message: options.message,
          },
        });
      case "whatsapp":
        return enqueueNotification({
          type: "whatsapp",
          userId: options.userId,
          companyId: options.companyId,
          payload: {
            chatId: options.chatId,
            messagingConfig: options.messagingConfig,
            title: options.title,
            message: options.message,
          },
        });
    }
  });

  await Promise.allSettled(tasks);
}

export { createInAppNotification } from "./in-app";
export { sendNotificationEmail } from "./email";

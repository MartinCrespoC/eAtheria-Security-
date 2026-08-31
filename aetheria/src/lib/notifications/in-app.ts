import { prisma } from "@/lib/db";

/**
 * Create an in-app notification record in the database.
 */
export async function createInAppNotification(
  userId: string,
  companyId: string,
  type: string,
  title: string,
  message: string,
  metadata?: Record<string, unknown>
): Promise<string> {
  const notification = await prisma.notification.create({
    data: {
      userId,
      companyId,
      type,
      title,
      message,
      metadata: metadata ? (JSON.parse(JSON.stringify(metadata)) as never) : undefined,
    },
  });

  return notification.id;
}

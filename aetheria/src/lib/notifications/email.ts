import { prisma } from "@/lib/db";
import { sendMail } from "@/lib/mail";

/**
 * Send an email notification to a user.
 * Looks up the user's email address and sends the notification.
 */
export async function sendNotificationEmail(
  userId: string,
  title: string,
  message: string,
  htmlBody?: string
): Promise<{ success: boolean }> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true, firstName: true },
  });

  if (!user?.email) {
    console.warn(`[NOTIFICATION] Cannot send email: user ${userId} not found or no email`);
    return { success: false };
  }

  const html = htmlBody || buildDefaultEmailHtml(title, message, user.firstName);

  const result = await sendMail({
    to: user.email,
    subject: title,
    html,
  });

  return { success: result.success !== false };
}

function buildDefaultEmailHtml(title: string, message: string, firstName: string): string {
  return `
    <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h1 style="color: #22d3ee; font-size: 24px; margin: 0;">EATHERIA</h1>
        <p style="color: #64748b; font-size: 12px; margin-top: 4px;">Security Platform</p>
      </div>
      <h2 style="color: white; font-size: 18px;">${title}</h2>
      <p style="color: #cbd5e1;">Hi ${firstName},</p>
      <p style="color: #cbd5e1;">${message}</p>
      <p style="color: #64748b; font-size: 12px; margin-top: 24px;">
        This is an automated notification from EATHERIA Security Platform.
      </p>
    </div>
  `;
}

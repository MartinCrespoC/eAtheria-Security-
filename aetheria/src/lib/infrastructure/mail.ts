import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const FROM = process.env.SMTP_FROM || "EATHERIA <noreply@aetheria.io>";

interface SendMailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export async function sendMail({ to, subject, html, text }: SendMailOptions) {
  if (!process.env.SMTP_USER) {
    console.warn("[MAIL] SMTP not configured, skipping email to:", to);
    return { success: false, reason: "SMTP not configured" };
  }

  try {
    await transporter.sendMail({
      from: FROM,
      to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, ""),
    });
    return { success: true };
  } catch (error) {
    console.error("[MAIL] Failed to send:", error);
    return { success: false, reason: String(error) };
  }
}

export function inviteUserEmail(email: string, companyName: string, inviterName: string, loginUrl: string) {
  return {
    to: email,
    subject: `Te han invitado a ${companyName} en EATHERIA`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <h1 style="color: #22d3ee; font-size: 24px; margin: 0;">EATHERIA</h1>
          <p style="color: #64748b; font-size: 12px; margin-top: 4px;">Security Platform</p>
        </div>
        <h2 style="color: white; font-size: 18px;">Has sido invitado</h2>
        <p><strong>${inviterName}</strong> te ha invitado a unirte a <strong>${companyName}</strong> en EATHERIA Security Platform.</p>
        <a href="${loginUrl}" style="display: inline-block; margin-top: 16px; padding: 12px 24px; background: linear-gradient(135deg, #06b6d4, #8b5cf6); color: white; text-decoration: none; border-radius: 8px; font-weight: 600;">
          Acceder a EATHERIA
        </a>
        <p style="color: #64748b; font-size: 12px; margin-top: 24px;">Si no esperabas esta invitación, puedes ignorar este correo.</p>
      </div>
    `,
  };
}

export function analysisCompleteEmail(
  email: string,
  appName: string,
  version: string,
  totalIssues: number,
  criticalCount: number,
  analysisUrl: string
) {
  const criticalBadge = criticalCount > 0
    ? `<span style="background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">${criticalCount} CRÍTICAS</span>`
    : "";

  return {
    to: email,
    subject: `Análisis completado: ${appName} v${version} — ${totalIssues} vulnerabilidades`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <h1 style="color: #22d3ee; font-size: 24px; margin: 0;">EATHERIA</h1>
        </div>
        <h2 style="color: white; font-size: 18px;">Análisis Completado</h2>
        <p>El análisis de <strong>${appName}</strong> versión <strong>${version}</strong> ha finalizado.</p>
        <div style="background: #1e293b; padding: 16px; border-radius: 8px; margin: 16px 0;">
          <p style="margin: 0; font-size: 24px; font-weight: bold; color: white;">${totalIssues} vulnerabilidades</p>
          ${criticalBadge}
        </div>
        <a href="${analysisUrl}" style="display: inline-block; margin-top: 12px; padding: 12px 24px; background: linear-gradient(135deg, #06b6d4, #8b5cf6); color: white; text-decoration: none; border-radius: 8px; font-weight: 600;">
          Ver Resultados
        </a>
      </div>
    `,
  };
}

export function securityAlertEmail(
  email: string,
  alertType: string,
  message: string
) {
  return {
    to: email,
    subject: `[ALERTA] ${alertType} — EATHERIA Security`,
    html: `
      <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <h1 style="color: #22d3ee; font-size: 24px; margin: 0;">EATHERIA</h1>
        </div>
        <div style="background: #7f1d1d; border: 1px solid #dc2626; padding: 16px; border-radius: 8px;">
          <h2 style="color: #fca5a5; font-size: 16px; margin: 0 0 8px 0;">Alerta de Seguridad: ${alertType}</h2>
          <p style="color: #fecaca; margin: 0;">${message}</p>
        </div>
      </div>
    `,
  };
}

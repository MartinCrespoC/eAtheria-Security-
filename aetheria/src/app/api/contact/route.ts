import { NextRequest, NextResponse } from "next/server";
import nodemailer from "nodemailer";
import { rateLimit, getClientIp } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);
  const rl = rateLimit(`contact:${ip}`, { maxRequests: 5, windowMs: 3_600_000 });
  if (!rl.success) {
    return NextResponse.json(
      { error: "Too many messages. Please try again later." },
      { status: 429 }
    );
  }

  try {
    const body = await req.json();
    const name = String(body.name || "").trim().slice(0, 120);
    const company = String(body.company || "").trim().slice(0, 120);
    const email = String(body.email || "").trim().toLowerCase().slice(0, 200);
    const message = String(body.message || "").trim().slice(0, 5000);

    if (!name || !email || !message) {
      return NextResponse.json(
        { error: "Name, email and message are required" },
        { status: 400 }
      );
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: "Invalid email" }, { status: 400 });
    }

    // Primary: FormSubmit relay (HTTPS). The droplet's outbound SMTP ports
    // are blocked at the network level, so direct SMTP cannot reach
    // smtp.office365.com. FormSubmit forwards the message over HTTPS.
    const formSubmitKey = process.env.FORMSUBMIT_KEY;
    if (formSubmitKey) {
      const fsRes = await fetch(`https://formsubmit.co/ajax/${formSubmitKey}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Referer: "https://eatheria.com/",
        },
        body: JSON.stringify({
          _subject: `[EATHERIA Contact] ${name}${company ? ` — ${company}` : ""}`,
          _replyto: email,
          _captcha: "false",
          name,
          company: company || "-",
          email,
          message,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const fsData = await fsRes.json().catch(() => null);
      if (!fsRes.ok || !fsData || fsData.success === "false") {
        console.error("[CONTACT] FormSubmit error:", fsRes.status, fsData);
        return NextResponse.json(
          { error: "Could not send the message. Please try again." },
          { status: 502 }
        );
      }
      return NextResponse.json({ ok: true });
    }

    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    if (!smtpUser || !smtpPass) {
      console.error("[CONTACT] SMTP_USER/SMTP_PASS not configured");
      return NextResponse.json(
        { error: "Contact service is not configured" },
        { status: 503 }
      );
    }

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.office365.com",
      port: Number(process.env.SMTP_PORT || 587),
      secure: false, // STARTTLS
      requireTLS: true,
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    });

    const to = process.env.CONTACT_TO || smtpUser;

    await transporter.sendMail({
      from: `EATHERIA Contact <${smtpUser}>`,
      to,
      replyTo: email,
      subject: `[EATHERIA Contact] ${name}${company ? ` — ${company}` : ""}`,
      text: `Name: ${name}\nCompany: ${company || "-"}\nEmail: ${email}\n\n${message}`,
      html: `
        <h3>New contact message — eatheria.com</h3>
        <p><b>Name:</b> ${escapeHtml(name)}</p>
        <p><b>Company:</b> ${escapeHtml(company || "-")}</p>
        <p><b>Email:</b> ${escapeHtml(email)}</p>
        <hr />
        <p>${escapeHtml(message).replace(/\n/g, "<br />")}</p>
      `,
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("[CONTACT] Send error:", error);
    return NextResponse.json(
      { error: "Could not send the message. Please try again." },
      { status: 500 }
    );
  }
}

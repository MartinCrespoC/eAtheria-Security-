/**
 * Admin notifications (registrations, purchases) via FormSubmit relay.
 *
 * The droplet's outbound SMTP ports are blocked at the network level, so we
 * deliver over HTTPS through FormSubmit to ADMIN_NOTIFY_EMAIL
 * (compras@eatheria.com). Failures are logged but never break the request.
 */

const DEFAULT_NOTIFY_EMAIL = "compras@eatheria.com";

export async function notifyAdmin(
  subject: string,
  fields: Record<string, string>
): Promise<void> {
  // Activated FormSubmit access key is preferred (email stays hidden and the
  // endpoint is stable); fall back to the plain email path.
  const target =
    process.env.ADMIN_FORMSUBMIT_KEY ||
    process.env.ADMIN_NOTIFY_EMAIL ||
    DEFAULT_NOTIFY_EMAIL;
  try {
    const res = await fetch(`https://formsubmit.co/ajax/${target}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Referer: "https://eatheria.com/",
      },
      body: JSON.stringify({
        _subject: subject,
        _captcha: "false",
        _template: "table",
        ...fields,
      }),
      signal: AbortSignal.timeout(12_000),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || data.success === "false") {
      console.error("[ADMIN_NOTIFY] delivery failed:", res.status, data);
    }
  } catch (err) {
    console.error("[ADMIN_NOTIFY] error:", err);
  }
}

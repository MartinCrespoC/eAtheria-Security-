"use client";

/**
 * Lightweight device fingerprint for free-plan abuse prevention.
 * Combines stable browser signals into a SHA-256 hash. Not crypto-grade
 * identity — a fraud signal layered with IP/domain/rate limits.
 */
export async function computeFingerprint(): Promise<string> {
  if (typeof window === "undefined") return "";

  const nav = window.navigator;
  const signals: string[] = [
    nav.userAgent,
    nav.language,
    (nav.languages || []).join(","),
    String(screen.width),
    String(screen.height),
    String(screen.colorDepth),
    String(new Date().getTimezoneOffset()),
    String((nav as { hardwareConcurrency?: number }).hardwareConcurrency ?? ""),
    String((nav as { deviceMemory?: number }).deviceMemory ?? ""),
    String((nav as { maxTouchPoints?: number }).maxTouchPoints ?? ""),
    navigator.platform ?? "",
  ];

  // Canvas signal — rendering differences are very stable per device
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 220;
    canvas.height = 40;
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(100, 1, 60, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("aetheria-fp 🛡️", 2, 15);
      signals.push(canvas.toDataURL());
    }
  } catch {
    // canvas blocked (rare privacy extensions) — continue without it
  }

  const raw = signals.join("|");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

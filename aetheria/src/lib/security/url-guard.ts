/**
 * SSRF guard: validates that a URL points to a public HTTP(S) resource.
 * Blocks private/loopback/link-local/reserved IPs, internal hostnames and
 * non-HTTP schemes (file:, gopher:, etc.). Used before any server-side fetch
 * of user-controlled URLs (sourceUrl ingestion, DAST targets).
 *
 * Residual risk: DNS rebinding (public hostname resolving to a private IP)
 * is NOT covered — would require resolving and pinning the address.
 */

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  // internal docker service names
  "aetheria-db",
  "aetheria-redis",
  "aetheria-app",
  "npm",
]);

function isBlockedIp(host: string): boolean {
  // IPv4 literal
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const [a, b] = host.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true; // this-net, private, loopback
    if (a === 169 && b === 254) return true; // link-local (cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast/reserved
    return false;
  }
  // IPv6 literal (bracketed by URL parser without brackets)
  const h = host.replace(/^\[|\]$/g, "");
  if (h === "::1" || h === "::") return true;
  if (h.startsWith("fe80") || h.startsWith("fd") || h.startsWith("fc")) return true;
  return false;
}

export function isSafeExternalUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host)) return false;
  if (host.endsWith(".internal") || host.endsWith(".local") || !host.includes(".")) return false;
  if (isBlockedIp(host)) return false;
  return true;
}

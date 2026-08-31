import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { checkRateLimit } from "@/lib/security/rate-limiter";
import { checkCompanyRateLimitWithMax } from "@/lib/security/company-rate-limit";

// Blocked IPs (loaded from API, cached in memory)
let blockedIPs: Set<string> = new Set();
let blockedIPsLastFetch = 0;
const BLOCKED_IPS_TTL = 60_000; // refresh every 60s

// Company rate limit cache (companyId → maxRequests, refreshed periodically)
const companyRateLimitCache = new Map<string, { maxRequests: number; fetchedAt: number }>();
const COMPANY_CACHE_TTL = 120_000; // 2 minutes

function getClientIP(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}


async function refreshBlockedIPs(baseUrl: string) {
  if (Date.now() - blockedIPsLastFetch < BLOCKED_IPS_TTL) return;
  try {
    const res = await fetch(`${baseUrl}/api/admin/blocked-ips`, {
      headers: { "x-internal-key": process.env.NEXTAUTH_SECRET || "" },
    });
    if (res.ok) {
      const data = await res.json();
      blockedIPs = new Set(data.ips || []);
    }
  } catch {
    // silently fail — keep existing list
  }
  blockedIPsLastFetch = Date.now();
}

/**
 * Fetch company rate limit setting from the internal API.
 * Falls back to 60 requests per minute if unavailable.
 */
async function getCompanyRateLimit(baseUrl: string, companyId: string): Promise<number> {
  const cached = companyRateLimitCache.get(companyId);
  if (cached && Date.now() - cached.fetchedAt < COMPANY_CACHE_TTL) {
    return cached.maxRequests;
  }

  try {
    const res = await fetch(`${baseUrl}/api/internal/company-settings?companyId=${companyId}`, {
      headers: { "x-internal-key": process.env.NEXTAUTH_SECRET || "" },
    });
    if (res.ok) {
      const data = await res.json();
      const maxRequests = data.rateLimitPerMinute || 60;
      companyRateLimitCache.set(companyId, { maxRequests, fetchedAt: Date.now() });
      return maxRequests;
    }
  } catch {
    // silently fail — use default
  }

  // Cache the default to avoid repeated fetches
  companyRateLimitCache.set(companyId, { maxRequests: 60, fetchedAt: Date.now() });
  return 60;
}

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const ip = getClientIP(req);

  // Setup guard: redirect to installer if not configured
  const isSetupRoute = pathname.startsWith("/setup") || pathname.startsWith("/api/setup");
  const isStaticAsset = pathname.startsWith("/_next") || pathname.includes(".");

  // Setup status check via loopback — never through the public edge
  // (a saturated reverse proxy must not soft-lock the platform).
  const statusUrl = `http://127.0.0.1:${process.env.PORT || 3000}/api/setup/status`;

  if (!isSetupRoute && !isStaticAsset) {
    // Individual mode: always verify setup status against the DB (single
    // instance, cheap loopback call). A stale cookie from a previous install
    // must never skip the wizard.
    {
      let dbSetupComplete = false;
      try {
        const statusRes = await fetch(statusUrl, {
          headers: { "x-internal-key": process.env.NEXTAUTH_SECRET || "" },
          signal: AbortSignal.timeout(3000),
        });
        if (statusRes.ok) {
          const statusData = await statusRes.json();
          dbSetupComplete = statusData.configured === true;
        }
      } catch {
        // If check fails, proceed to setup
      }

      if (dbSetupComplete) {
        // Setup IS complete — set cookie and continue (no redirect)
        const response = NextResponse.next();
        response.cookies.set("aetheria_setup_complete", "true", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          maxAge: 60 * 60 * 24 * 365,
          path: "/",
        });
        return response;
      }

      // Only redirect non-API requests to setup page
      if (!pathname.startsWith("/api/")) {
        return NextResponse.redirect(new URL("/setup", req.url));
      } else {
        return NextResponse.json(
          { error: "Platform not configured" },
          { status: 503 }
        );
      }
    }
  }

  // Post-setup lockdown: once configured, the installer is closed for good.
  // Page routes redirect to /login; API routes 403 (defense-in-depth — each
  // /api/setup route also guards individually). /api/setup/status stays open:
  // it only exposes {configured:true} and the proxy itself depends on it.
  if (isSetupRoute && pathname !== "/api/setup/status") {
    let configured = req.cookies.get("aetheria_setup_complete")?.value === "true";
    // Validate the cookie against the DB on page requests — a stale cookie
    // from a previous install must not softlock a fresh setup.
    const needsDbCheck = !configured || !pathname.startsWith("/api/");
    if (needsDbCheck) {
      try {
        const statusRes = await fetch(statusUrl, {
          headers: { "x-internal-key": process.env.NEXTAUTH_SECRET || "" },
          signal: AbortSignal.timeout(3000),
        });
        if (statusRes.ok) {
          const statusData = await statusRes.json();
          configured = statusData.configured === true;
        }
      } catch {
        configured = false; // DB unreachable → installer stays open
      }
    }
    if (configured) {
      if (pathname.startsWith("/api/")) {
        return NextResponse.json(
          { error: "Setup is already complete" },
          { status: 403 }
        );
      }
      return NextResponse.redirect(new URL("/login", req.url));
    }
    // Stale cookie from a previous install on a fresh DB — clear it.
    if (req.cookies.get("aetheria_setup_complete")?.value === "true") {
      const response = NextResponse.next();
      response.cookies.delete("aetheria_setup_complete");
      return response;
    }
  }

  // Skip rate limiting and blocked-IP check for auth endpoints, setup routes, and internal requests
  const isAuthRoute = pathname.startsWith("/api/auth/");
  const isInviteRoute = pathname.startsWith("/api/invite/") || pathname.startsWith("/invite/");
  const isInternalRequest = req.headers.get("x-internal-key") === (process.env.NEXTAUTH_SECRET || "");

  if (!isAuthRoute && !isInternalRequest && !isSetupRoute) {
    // Refresh blocked IPs list periodically
    await refreshBlockedIPs(req.nextUrl.origin);

    // Check if IP is blocked
    if (blockedIPs.has(ip)) {
      return NextResponse.json(
        { error: "Access denied" },
        { status: 403 }
      );
    }

    // Rate limiting on API routes (exclude auth and invite routes)
    if (pathname.startsWith("/api/") && !isInviteRoute) {
      const rateLimitResult = checkRateLimit(ip, pathname);
      if (!rateLimitResult.allowed) {
        return NextResponse.json(
          { error: "Too many requests" },
          {
            status: 429,
            headers: {
              "Retry-After": String(rateLimitResult.retryAfter || 60),
              "X-RateLimit-Remaining": "0",
            }
          }
        );
      }
    }
  }

  // Security headers
  const response = NextResponse.next();
  response.headers.delete("x-powered-by");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-XSS-Protection", "1; mode=block");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  response.headers.set(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );

  // NOTE: Content-Security-Policy lives in next.config.ts headers()
  // (framework-level headers override middleware response headers, so a
  // CSP set here would never reach the client). Keep a single source there.

  // Protected routes
  const protectedPaths = ["/dashboard", "/admin", "/api/admin", "/api/dashboard", "/api/invite"];
  const isProtected = protectedPaths.some((path) => pathname.startsWith(path));

  // Admin-only routes
  const adminPaths = ["/admin", "/api/admin"];
  const isAdmin = adminPaths.some((path) => pathname.startsWith(path));

  if (isProtected) {
    const token = await getToken({
      req,
      secret: process.env.NEXTAUTH_SECRET,
      cookieName: "next-auth.session-token",
    });

    if (!token) {
      // Allow invite page to be accessed without auth
      if (isInviteRoute) {
        return response;
      }
      const url = new URL("/login", req.url);
      url.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(url);
    }

    // Check if user is blocked
    if (token.isBlocked) {
      return NextResponse.json(
        { error: "Account blocked" },
        { status: 403 }
      );
    }

    if (isAdmin && !token.isSystemAdmin) {
      return NextResponse.redirect(new URL("/dashboard", req.url));
    }

    // Company-level rate limiting (in addition to IP-based rate limiting)
    if (pathname.startsWith("/api/") && !isAuthRoute && !isInternalRequest && token.companyId) {
      const companyMaxRequests = await getCompanyRateLimit(req.nextUrl.origin, token.companyId);
      const companyRateResult = checkCompanyRateLimitWithMax(
        token.companyId,
        pathname,
        companyMaxRequests
      );

      if (!companyRateResult.allowed) {
        console.warn(
          `[RATE LIMIT] Company ${token.companyId} exceeded rate limit (${companyMaxRequests}/min) on ${pathname}`
        );
        return NextResponse.json(
          { error: "Company rate limit exceeded" },
          {
            status: 429,
            headers: {
              "Retry-After": "60",
              "X-RateLimit-Remaining": "0",
            }
          }
        );
      }
    }

    // Domain Separation: Enforce company isolation on API calls
    if (pathname.startsWith("/api/") && !pathname.startsWith("/api/auth/") && !pathname.startsWith("/api/admin/")) {
      // Extract companyId from request (query param or body)
      const url = new URL(req.url);
      const queryCompanyId = url.searchParams.get("companyId");

      // If companyId is in query and doesn't match user's company (and user is not system admin)
      if (queryCompanyId && queryCompanyId !== token.companyId && !token.isSystemAdmin) {
        // Enhanced IDOR logging with full context
        console.warn(
          `[DOMAIN SEPARATION] IDOR Attempt - ` +
          `User: ${token.id} (email: ${token.email}), ` +
          `User Company: ${token.companyId}, ` +
          `Target Company: ${queryCompanyId}, ` +
          `Endpoint: ${pathname}, ` +
          `IP: ${ip}, ` +
          `UserAgent: ${req.headers.get("user-agent") || "unknown"}`
        );

        return NextResponse.json(
          { error: "Access denied: Company isolation violation" },
          { status: 403 }
        );
      }
    }
  }

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};

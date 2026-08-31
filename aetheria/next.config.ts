import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  // Client-hardening: never ship sourcemaps in production (DevTools would
  // otherwise reconstruct readable sources) and don't advertise the stack.
  productionBrowserSourceMaps: false,
  poweredByHeader: false,
  // Security headers for every response. NOTE: DevTools/Tampermonkey run
  // below the web platform — no header can block them; real protection is
  // that every security decision is enforced server-side. These headers
  // stop the classes of attacks headers CAN stop (clickjacking, MIME
  // sniffing, XSS via injected scripts, referrer leakage).
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()",
          },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              // Next.js hydration requires inline scripts; keep the rest tight.
              // 'unsafe-eval' ONLY in development — React dev uses eval() for
              // debugging (callstack reconstruction). Production never needs it.
              // challenges.cloudflare.com = Turnstile bot protection widget.
              // js.stripe.com = Stripe.js, cdn.jsdelivr.net = landing animations,
              // static.cloudflareinsights.com = Cloudflare Web Analytics beacon.
              `script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""} https://challenges.cloudflare.com https://js.stripe.com https://cdn.jsdelivr.net https://static.cloudflareinsights.com`,
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "img-src 'self' data: blob: https:",
              "font-src 'self' data: https://fonts.gstatic.com",
              // cloudflareinsights.com = beacon RUM reporting endpoint.
              "connect-src 'self' wss: https://challenges.cloudflare.com https://api.stripe.com https://*.google.com https://*.googleapis.com https://cloudflareinsights.com",
              "frame-src 'self' https://challenges.cloudflare.com https://js.stripe.com https://hooks.stripe.com",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              "object-src 'none'",
            ].join("; "),
          },
        ],
      },
    ];
  },
  // Baileys (@whiskeysockets/baileys) is a pure-Node WhatsApp Web client that
  // relies on dynamic requires / native-ish deps that break when webpack tries
  // to bundle it. Keep it external so it is loaded straight from node_modules
  // on the server.
  serverExternalPackages: ["@whiskeysockets/baileys"],
  experimental: {
    serverActions: {
      bodySizeLimit: "1gb",
    },
    // The middleware ("proxy" in Next.js 16) buffers the request body in memory,
    // capped at 10MB by default. Large source-code uploads (up to 1GB) get
    // truncated, which corrupts the multipart body and makes request.formData()
    // throw "Failed to parse body as FormData". Raise the cap to match uploads.
    proxyClientMaxBodySize: "1gb",
  },
};

export default nextConfig;

import type { Metadata } from "next";
// Local Geist fonts (bundled via the `geist` package) — no build-time network
// fetch, unlike `next/font/google`, so builds work offline / in Docker.
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { cookies } from "next/headers";
import { AuthProvider } from "@/components/providers/session-provider";
import { LanguageProvider } from "@/components/providers/language-provider";
import { DEFAULT_LOCALE, isLocale, type Locale } from "@/lib/i18n/types";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXTAUTH_URL || "https://eatheria.com"),
  title: {
    default: "EATHERIA Security — AI SAST, DAST & SCA | Fortify Alternative",
    template: "%s | EATHERIA Security",
  },
  description:
    "AI-validated SAST, DAST & SCA scanning — fewer false positives, CI/CD ready, SBOM and OWASP Top 10 reports. The modern Fortify alternative. Free scan included.",
  keywords:
    "SAST, DAST, SCA, application security platform, vulnerability scanner, fortify alternative, snyk alternative, checkmarx alternative, static code analysis, dynamic application security testing, software composition analysis, AI security scanning, false positive reduction, CWE, OWASP Top 10, SBOM, PCI DSS, NIST, DevSecOps, CI/CD security, code vulnerability detection, escaner de vulnerabilidades, seguridad de aplicaciones, analisis de codigo estatico",
  authors: [{ name: "EATHERIA Security" }],
  creator: "EATHERIA Security",
  alternates: {
    canonical: "/",
  },
  openGraph: {
    title: "EATHERIA Security — AI-Powered SAST, DAST & SCA Platform",
    description:
      "AI-validated application security scanning. SAST, DAST, SCA, SBOM and CI/CD integration — the modern Fortify alternative, from $35/mo.",
    type: "website",
    locale: "en_US",
    alternateLocale: "es_MX",
    siteName: "EATHERIA Security",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "EATHERIA Security — AI-Powered AppSec Platform",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "EATHERIA Security — AI-Powered SAST, DAST & SCA Platform",
    description:
      "AI-validated application security scanning — the modern Fortify alternative, from $35/mo.",
    images: ["/og-image.png"],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const cookieStore = await cookies();
  const raw = cookieStore.get("aetheria-locale")?.value;
  const locale: Locale = isLocale(raw) ? raw : DEFAULT_LOCALE;

  return (
    <html
      lang={locale}
      className={`${GeistSans.variable} ${GeistMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full bg-slate-950 text-slate-100 flex flex-col">
        <LanguageProvider initialLocale={locale}>
          <AuthProvider>{children}</AuthProvider>
        </LanguageProvider>
      </body>
    </html>
  );
}

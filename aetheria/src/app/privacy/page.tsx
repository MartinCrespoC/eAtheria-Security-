import type { Metadata } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { DEFAULT_LOCALE, isLocale, type Locale } from "@/lib/i18n/types";
import { LEGAL_CONTENT } from "@/lib/legal-content";
import { LegalDocument } from "@/components/legal/legal-document";
import { Logo } from "@/components/brand/logo";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "EATHERIA Privacy Policy: data we collect, purposes, source code processing, sub-processors, cookies, retention, international transfers and your rights.",
  alternates: { canonical: "/privacy" },
};

export default async function PrivacyPage() {
  const cookieStore = await cookies();
  const raw = cookieStore.get("aetheria-locale")?.value;
  const locale: Locale = isLocale(raw) ? raw : DEFAULT_LOCALE;
  const doc = LEGAL_CONTENT.privacy[locale];

  return (
    <div className="min-h-screen bg-slate-950">
      <header className="border-b border-slate-800/60 py-4">
        <div className="container mx-auto px-6">
          <Link href="/">
            <Logo />
          </Link>
        </div>
      </header>
      <main className="container mx-auto px-6 py-16 max-w-3xl">
        <LegalDocument doc={doc} />
      </main>
    </div>
  );
}

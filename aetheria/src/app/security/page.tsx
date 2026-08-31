import type { Metadata } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { DEFAULT_LOCALE, isLocale, type Locale } from "@/lib/i18n/types";
import { LEGAL_CONTENT } from "@/lib/legal-content";
import { LegalDocument } from "@/components/legal/legal-document";
import { Logo } from "@/components/brand/logo";

export const metadata: Metadata = {
  title: "Security & Responsible Disclosure",
  description:
    "EATHERIA security measures and responsible vulnerability disclosure program: SRP authentication, encryption, isolation, incident response and safe harbor rules.",
  alternates: { canonical: "/security" },
};

export default async function SecurityPage() {
  const cookieStore = await cookies();
  const raw = cookieStore.get("aetheria-locale")?.value;
  const locale: Locale = isLocale(raw) ? raw : DEFAULT_LOCALE;
  const doc = LEGAL_CONTENT.security[locale];

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

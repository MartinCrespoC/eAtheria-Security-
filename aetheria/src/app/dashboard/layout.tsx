import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { DashboardShell } from "@/components/dashboard/dashboard-shell";
import { ThemeProvider } from "@/components/providers/theme-provider";
import { LanguageProvider } from "@/components/providers/language-provider";
import { isLocale, DEFAULT_LOCALE } from "@/lib/i18n/types";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const theme = (session.user.theme as "dark" | "light") ?? "dark";
  const locale = isLocale(session.user.locale) ? session.user.locale : DEFAULT_LOCALE;

  return (
    <LanguageProvider initialLocale={locale}>
      <ThemeProvider initialTheme={theme}>
        <DashboardShell user={session.user}>{children}</DashboardShell>
      </ThemeProvider>
    </LanguageProvider>
  );
}

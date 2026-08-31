"use client";

import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { translate, translateArray } from "@/lib/i18n/dict";
import { DEFAULT_LOCALE, isLocale, type Locale } from "@/lib/i18n/types";

const COOKIE_NAME = "aetheria-locale";

interface LanguageContextType {
  locale: Locale;
  setLocale: (l: Locale) => void;
  /** Translate a dot-path key, e.g. t("landing.hero.titleA") */
  t: (path: string) => string;
  /** Translate an array key (FAQ items, feature lists...) */
  ta: <T = string>(path: string) => T[];
}

const LanguageContext = createContext<LanguageContextType>({
  locale: DEFAULT_LOCALE,
  setLocale: () => {},
  t: (p) => p,
  ta: () => [],
});

function readCookie(): Locale | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${COOKIE_NAME}=([^;]+)`));
  return match && isLocale(match[1]) ? match[1] : null;
}

export function LanguageProvider({
  children,
  initialLocale = DEFAULT_LOCALE,
}: {
  children: React.ReactNode;
  initialLocale?: Locale;
}) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale);

  useEffect(() => {
    // A client-side cookie choice (anonymous visitors) wins over the
    // server-provided initial value.
    const fromCookie = readCookie();
    if (fromCookie && fromCookie !== locale) setLocaleState(fromCookie);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    // Persist for anonymous visitors (portal) via cookie
    document.cookie = `${COOKIE_NAME}=${l}; path=/; max-age=31536000; samesite=lax`;
    // Persist to user preferences when logged in (best-effort)
    fetch("/api/users/locale", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ locale: l }),
    }).catch(() => {});
  }, []);

  const t = useCallback((path: string) => translate(locale, path), [locale]);
  const ta = useCallback(
    <T,>(path: string) => translateArray<T>(locale, path),
    [locale]
  );

  return (
    <LanguageContext.Provider value={{ locale, setLocale, t, ta }}>
      {children}
    </LanguageContext.Provider>
  );
}

export const useLanguage = () => useContext(LanguageContext);

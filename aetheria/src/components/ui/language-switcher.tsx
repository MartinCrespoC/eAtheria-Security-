"use client";

import { useState, useRef, useEffect } from "react";
import { Check, ChevronDown } from "lucide-react";
import { useLanguage } from "@/components/providers/language-provider";
import type { Locale } from "@/lib/i18n/types";

function FlagUS({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 16" className={className} aria-hidden="true">
      <rect width="24" height="16" rx="2" fill="#b22234" />
      {Array.from({ length: 6 }).map((_, i) => (
        <rect key={i} y={i * 2.46 + 1.23} width="24" height="1.23" fill="#fff" />
      ))}
      <rect width="10" height="8.6" rx="1" fill="#3c3b6e" />
      {Array.from({ length: 12 }).map((_, i) => (
        <circle
          key={i}
          cx={1.4 + (i % 4) * 2.4}
          cy={1.6 + Math.floor(i / 4) * 2.6}
          r="0.55"
          fill="#fff"
        />
      ))}
    </svg>
  );
}

function FlagMX({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 16" className={className} aria-hidden="true">
      <rect width="8" height="16" rx="2" fill="#006847" />
      <rect x="8" width="8" height="16" fill="#fff" />
      <rect x="16" width="8" height="16" rx="2" fill="#ce1126" />
      <rect x="8" width="8" height="16" fill="#fff" />
      <circle cx="12" cy="8" r="2" fill="#8c6d1f" opacity="0.85" />
    </svg>
  );
}

const OPTIONS: { locale: Locale; label: string; Flag: typeof FlagUS }[] = [
  { locale: "en", label: "English", Flag: FlagUS },
  { locale: "es", label: "Español", Flag: FlagMX },
];

export function LanguageSwitcher({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale, t } = useLanguage();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const current = OPTIONS.find((o) => o.locale === locale) ?? OPTIONS[0];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        title={t("dashboard.header.language")}
        className="h-9 px-2 rounded-lg border border-border hover:bg-surface-hover text-text-secondary hover:text-text-primary flex items-center gap-1.5 transition-colors"
      >
        <current.Flag className="h-3.5 w-5 rounded-[3px] shadow-sm" />
        {!compact && <span className="text-xs font-medium uppercase">{current.locale}</span>}
        <ChevronDown className="h-3 w-3" />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-40 rounded-lg border border-border bg-surface shadow-2xl z-50 overflow-hidden">
          {OPTIONS.map(({ locale: l, label, Flag }) => (
            <button
              key={l}
              onClick={() => {
                setLocale(l);
                setOpen(false);
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-colors ${
                l === locale
                  ? "bg-cyan-500/10 text-accent"
                  : "text-text-primary hover:bg-surface-hover"
              }`}
            >
              <Flag className="h-3.5 w-5 rounded-[3px] shadow-sm" />
              <span className="flex-1 text-left">{label}</span>
              {l === locale && <Check className="h-3.5 w-3.5" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

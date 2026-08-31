"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { useLanguage } from "@/components/providers/language-provider";
import { LEGAL_CONTENT, type LegalDocId } from "@/lib/legal-content";
import { LegalDocument } from "@/components/legal/legal-document";

export function LegalModal({
  docId,
  open,
  onClose,
}: {
  docId: LegalDocId | null;
  open: boolean;
  onClose: () => void;
}) {
  const { locale } = useLanguage();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open || !docId) return null;

  const doc = LEGAL_CONTENT[docId][locale];

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label={doc.title}
    >
      <div
        className="relative w-full max-w-3xl max-h-[85vh] overflow-y-auto rounded-2xl border border-slate-700/60 bg-slate-950 shadow-2xl shadow-cyan-500/10 p-6 md:p-10"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="sticky top-0 float-right ml-auto flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900 border border-slate-700/60 text-slate-400 hover:text-white hover:border-cyan-500/50 transition-colors"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>
        <LegalDocument doc={doc} />
      </div>
    </div>
  );
}

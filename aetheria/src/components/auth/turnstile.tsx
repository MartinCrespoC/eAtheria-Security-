"use client";

import { useEffect, useRef } from "react";

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement,
        opts: { sitekey: string; callback: (token: string) => void; theme?: string; action?: string }
      ) => string;
      reset: (id?: string) => void;
    };
  }
}

export function resetTurnstile() {
  window.turnstile?.reset();
}

/**
 * Cloudflare Turnstile widget (invisible-ish bot check, free).
 * Renders nothing when NEXT_PUBLIC_TURNSTILE_SITE_KEY is not set (dev).
 */
export function Turnstile({ onToken }: { onToken: (token: string) => void }) {
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
  const containerRef = useRef<HTMLDivElement>(null);
  const renderedRef = useRef(false);

  useEffect(() => {
    if (!siteKey || !containerRef.current || renderedRef.current) return;

    function render() {
      if (renderedRef.current || !containerRef.current || !window.turnstile) return;
      renderedRef.current = true;
      window.turnstile.render(containerRef.current, {
        sitekey: siteKey!,
        callback: onToken,
        theme: "dark",
        action: "turnstile-spin-v2",
      });
    }

    if (window.turnstile) {
      render();
      return;
    }

    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
    script.async = true;
    script.onload = render;
    document.head.appendChild(script);
  }, [siteKey, onToken]);

  if (!siteKey) return null;
  return (
    <div
      ref={containerRef}
      className="cf-turnstile flex justify-center"
      data-action="turnstile-spin-v2"
    />
  );
}

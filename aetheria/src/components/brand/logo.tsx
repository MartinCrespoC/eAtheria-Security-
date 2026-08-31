import { useId } from "react";
import { cn } from "@/lib/utils";

export function Logo({
  className,
  showText = true,
  size = "md",
}: {
  className?: string;
  showText?: boolean;
  size?: "sm" | "md" | "lg" | "xl";
}) {
  // Unique ids per instance: multiple logos on one page share id="logoGrad"
  // otherwise, and url(#logoGrad) resolves to the first match — if that
  // instance unmounts or is hidden, the rest render without gradient (the
  // "broken logo" bug).
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const gradId = `logoGrad-${uid}`;
  const glowId = `glow-${uid}`;

  const sizeMap = {
    sm: { icon: "h-6 w-6", text: "text-lg" },
    md: { icon: "h-8 w-8", text: "text-xl" },
    lg: { icon: "h-12 w-12", text: "text-3xl" },
    xl: { icon: "h-20 w-20", text: "text-5xl" },
  };

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className={cn("relative", sizeMap[size].icon)}>
        <svg
          viewBox="0 0 40 40"
          fill="none"
          className="w-full h-full animate-shield-pulse"
        >
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="50%" stopColor="#8b5cf6" />
              <stop offset="100%" stopColor="#ec4899" />
            </linearGradient>
            <filter id={glowId}>
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {/* Outer shield */}
          <path
            d="M20 2 L35 8 L35 20 C35 28 28 36 20 38 C12 36 5 28 5 20 L5 8 Z"
            stroke={`url(#${gradId})`}
            strokeWidth="2"
            fill="rgba(6, 182, 212, 0.1)"
            filter={`url(#${glowId})`}
          />
          {/* Inner A */}
          <path
            d="M14 28 L20 12 L26 28 M16 22 L24 22"
            stroke={`url(#${gradId})`}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="none"
            filter={`url(#${glowId})`}
          />
          {/* Core dot */}
          <circle cx="20" cy="20" r="1.5" fill="#22d3ee">
            <animate
              attributeName="r"
              values="1.5;2.5;1.5"
              dur="2s"
              repeatCount="indefinite"
            />
          </circle>
        </svg>
      </div>
      {showText && (
        <span
          className={cn(
            "font-black tracking-wider gradient-text",
            sizeMap[size].text
          )}
        >
          EATHERIA
        </span>
      )}
    </div>
  );
}

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default:
          "border-cyan-500/30 bg-cyan-500/10 text-accent",
        secondary:
          "border-purple-500/30 bg-purple-500/10 text-purple-400",
        destructive:
          "border-red-500/30 bg-red-500/10 text-red-400",
        success:
          "border-green-500/30 bg-green-500/10 text-green-400",
        warning:
          "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
        outline:
          "border-border text-text-primary",
        critical:
          "border-red-500/50 bg-red-500/20 text-red-300 shadow-sm shadow-red-500/30",
        high:
          "border-orange-500/50 bg-orange-500/20 text-orange-300",
        medium:
          "border-yellow-500/50 bg-yellow-500/20 text-yellow-300",
        low:
          "border-blue-500/50 bg-blue-500/20 text-blue-300",
        info:
          "border-slate-500/50 bg-slate-500/20 text-text-primary",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };

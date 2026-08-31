import type { ScanLevel } from "@/lib/analysis/scan-knowledge";

/**
 * Plan-based scan level gating. Ordered from least to most expensive
 * (deeper scans burn more AI tokens, so higher levels require higher plans).
 */
const LEVEL_ORDER: ScanLevel[] = ["STATIC", "LIGHTWEIGHT", "DEEP"];

const PLAN_MAX_LEVEL: Record<string, ScanLevel> = {
  free: "STATIC",
  starter: "LIGHTWEIGHT",
  professional: "DEEP",
  enterprise: "DEEP",
  ultimate: "DEEP",
};

export function maxScanLevelForLicense(licenseName: string): ScanLevel {
  return PLAN_MAX_LEVEL[licenseName] ?? "STATIC";
}

export function isScanLevelAllowed(licenseName: string, level: ScanLevel): boolean {
  return LEVEL_ORDER.indexOf(level) <= LEVEL_ORDER.indexOf(maxScanLevelForLicense(licenseName));
}

export const SCAN_LEVEL_LABELS: Record<ScanLevel, string> = {
  STATIC: "L1 — Estático (patrones por archivo)",
  LIGHTWEIGHT: "L2 — Ligero (flujo de datos intra-archivo)",
  DEEP: "L3 — Profundo (taint tracking entre archivos)",
};

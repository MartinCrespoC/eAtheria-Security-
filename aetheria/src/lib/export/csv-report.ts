/**
 * CSV Export — Flat findings export with BOM for Excel compatibility.
 */

interface CsvVuln {
  severity: string;
  confidence: string;
  category: string;
  title: string;
  description: string;
  filePath: string | null;
  lineStart: number | null;
  cweId: string | null;
  cveId: string | null;
  owaspTop10: string | null;
  detectionMethod: string | null;
  deltaStatus: string | null;
  isFalsePositive: boolean;
  status: string;
  smartFix: string | null;
  rootCause: string | null;
  packageName: string | null;
  packageVersion: string | null;
  ecosystem: string | null;
}

const COLUMNS: { key: keyof CsvVuln; label: string }[] = [
  { key: "severity", label: "Severidad" },
  { key: "confidence", label: "Confianza" },
  { key: "category", label: "Categoría" },
  { key: "title", label: "Título" },
  { key: "description", label: "Descripción" },
  { key: "filePath", label: "Archivo" },
  { key: "lineStart", label: "Línea" },
  { key: "cweId", label: "CWE" },
  { key: "cveId", label: "CVE" },
  { key: "owaspTop10", label: "OWASP" },
  { key: "detectionMethod", label: "Método Detección" },
  { key: "deltaStatus", label: "Delta" },
  { key: "isFalsePositive", label: "Falso Positivo" },
  { key: "status", label: "Estado" },
  { key: "rootCause", label: "Causa Raíz" },
  { key: "packageName", label: "Paquete" },
  { key: "packageVersion", label: "Versión Paquete" },
  { key: "ecosystem", label: "Ecosistema" },
  { key: "smartFix", label: "Fix IA" },
];

function escapeCsv(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function generateCsvReport(vulns: CsvVuln[]): string {
  const BOM = "\uFEFF";
  const header = COLUMNS.map((c) => escapeCsv(c.label)).join(",");
  const rows = vulns.map((v) =>
    COLUMNS.map((c) => escapeCsv(v[c.key])).join(",")
  );
  return BOM + [header, ...rows].join("\r\n");
}

export function downloadCsvReport(vulns: CsvVuln[], appName: string): void {
  const csv = generateCsvReport(vulns);
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${appName.replace(/\s+/g, "_")}_hallazgos.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

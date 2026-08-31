/**
 * Server-side PDF report generator (Node runtime).
 * Mirrors the client layout (export/pdf-report.ts) and adds a per-finding
 * detail section plus an AI-triage false-positive appendix, so CI pipelines
 * can download a complete audit document via the v1 API.
 */
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

export interface PdfVuln {
  severity: string;
  title: string;
  category: string;
  cweId: string | null;
  owaspTop10: string | null;
  filePath: string | null;
  lineStart: number | null;
  confidence: string;
  description: string;
  smartFix: string | null;
  fixExplanation: string | null;
  isFalsePositive: boolean;
  fpReason: string | null;
  aiValidated: boolean;
  aiConfidence: number | null;
}

export interface PdfAnalysis {
  id: string;
  status: string;
  scanTypes: unknown;
  duration: number | null;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  falsePositives: number;
  createdAt: string | Date;
  appVersion: {
    version: string;
    application: { name: string };
  };
  vulnerabilities: PdfVuln[];
}

const SEV_COLORS: Record<string, [number, number, number]> = {
  CRITICAL: [220, 38, 38],
  HIGH: [234, 88, 12],
  MEDIUM: [217, 119, 6],
  LOW: [37, 99, 235],
  INFO: [100, 116, 139],
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function buildPdfReport(analysis: PdfAnalysis): Buffer {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();

  // ── Header ──
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageW, 35, "F");
  doc.setTextColor(6, 182, 212);
  doc.setFontSize(18);
  doc.text("EATHERIA Security", 14, 15);
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.text("Reporte de Análisis de Seguridad", 14, 23);
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(8);
  doc.text(`Generado: ${new Date().toLocaleString("es-ES")}`, 14, 30);

  // ── App info ──
  let y = 45;
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(12);
  doc.text(`Aplicación: ${analysis.appVersion.application.name}`, 14, y);
  y += 6;
  doc.setFontSize(9);
  doc.setTextColor(71, 85, 105);
  const scanTypes = Array.isArray(analysis.scanTypes) ? analysis.scanTypes.join(", ") : "";
  doc.text(`Versión: ${analysis.appVersion.version}  |  Tipos: ${scanTypes}  |  Duración: ${analysis.duration ?? "N/A"}s`, 14, y);
  y += 6;
  doc.text(`Fecha: ${new Date(analysis.createdAt).toLocaleString("es-ES")}  |  Estado: ${analysis.status}  |  ID: ${analysis.id}`, 14, y);
  y += 10;

  // ── Summary box ──
  doc.setFillColor(241, 245, 249);
  doc.roundedRect(14, y, pageW - 28, 22, 2, 2, "F");
  const cols = [
    { label: "CRÍTICAS", val: analysis.criticalCount, color: SEV_COLORS.CRITICAL },
    { label: "ALTAS", val: analysis.highCount, color: SEV_COLORS.HIGH },
    { label: "MEDIAS", val: analysis.mediumCount, color: SEV_COLORS.MEDIUM },
    { label: "BAJAS", val: analysis.lowCount, color: SEV_COLORS.LOW },
    { label: "INFO", val: analysis.infoCount, color: SEV_COLORS.INFO },
    { label: "FP", val: analysis.falsePositives, color: [100, 116, 139] as [number, number, number] },
  ];
  const colW = (pageW - 28) / cols.length;
  cols.forEach((c, i) => {
    const cx = 14 + colW * i + colW / 2;
    doc.setTextColor(c.color[0], c.color[1], c.color[2]);
    doc.setFontSize(16);
    doc.text(String(c.val), cx, y + 10, { align: "center" });
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(c.label, cx, y + 17, { align: "center" });
  });
  y += 30;

  const kept = analysis.vulnerabilities.filter((v) => !v.isFalsePositive);
  const fps = analysis.vulnerabilities.filter((v) => v.isFalsePositive);
  const sorted = [...kept].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  // ── Summary table ──
  if (sorted.length > 0) {
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59);
    doc.text(`Vulnerabilidades (${sorted.length})`, 14, y);
    y += 4;

    autoTable(doc, {
      startY: y,
      head: [["Sev", "Título", "CWE", "OWASP", "Archivo", "Confianza"]],
      body: sorted.map((v) => [
        v.severity,
        v.title.length > 50 ? v.title.slice(0, 47) + "..." : v.title,
        v.cweId || "-",
        v.owaspTop10 || "-",
        v.filePath ? `${v.filePath}${v.lineStart ? ":" + v.lineStart : ""}` : "-",
        v.confidence,
      ]),
      styles: { fontSize: 7, cellPadding: 2 },
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7 },
      columnStyles: { 0: { cellWidth: 18 }, 1: { cellWidth: 55 }, 4: { cellWidth: 40 } },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 0) {
          const sev = data.cell.raw as string;
          const color = SEV_COLORS[sev] || SEV_COLORS.INFO;
          data.cell.styles.textColor = color;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // ── Per-finding detail ──
  if (sorted.length > 0) {
    if (y > pageH - 40) { doc.addPage(); y = 20; }
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59);
    doc.text("Detalle de hallazgos", 14, y);
    y += 6;

    sorted.forEach((v, idx) => {
      const descLines = doc.splitTextToSize(v.description || "—", pageW - 34) as string[];
      const fixText = v.fixExplanation || v.smartFix || "";
      const fixLines = fixText ? (doc.splitTextToSize(fixText, pageW - 34) as string[]).slice(0, 8) : [];
      const blockH = 12 + Math.min(descLines.length, 8) * 4 + (fixLines.length ? 5 + fixLines.length * 4 : 0);
      if (y + blockH > pageH - 20) { doc.addPage(); y = 20; }

      const color = SEV_COLORS[v.severity] || SEV_COLORS.INFO;
      doc.setFillColor(color[0], color[1], color[2]);
      doc.rect(14, y - 4, 3, 5, "F");
      doc.setFontSize(9);
      doc.setTextColor(30, 41, 59);
      const loc = v.filePath ? `${v.filePath}${v.lineStart ? ":" + v.lineStart : ""}` : "-";
      doc.text(`${idx + 1}. [${v.severity}] ${v.title}`, 20, y);
      y += 4;
      doc.setFontSize(7);
      doc.setTextColor(100, 116, 139);
      doc.text(`${v.cweId || "-"} · ${v.owaspTop10 || "-"} · ${loc}${v.aiValidated ? ` · AI:${v.aiConfidence ?? "-"}%` : ""}`, 20, y);
      y += 4;
      doc.setTextColor(51, 65, 85);
      doc.text(descLines.slice(0, 8), 20, y);
      y += Math.min(descLines.length, 8) * 4;
      if (fixLines.length) {
        y += 1;
        doc.setTextColor(5, 122, 85);
        doc.text("Fix sugerido:", 20, y);
        y += 4;
        doc.setTextColor(51, 65, 85);
        doc.text(fixLines, 20, y);
        y += fixLines.length * 4;
      }
      y += 4;
    });
  }

  // ── AI triage FP appendix ──
  if (fps.length > 0) {
    if (y > pageH - 50) { doc.addPage(); y = 20; }
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59);
    doc.text(`Falsos positivos descartados (${fps.length})`, 14, y);
    y += 4;
    autoTable(doc, {
      startY: y,
      head: [["Título", "CWE", "Archivo", "Razón (triage)"]],
      body: fps.map((v) => [
        v.title.length > 40 ? v.title.slice(0, 37) + "..." : v.title,
        v.cweId || "-",
        v.filePath ? v.filePath.split("/").pop() ?? "-" : "-",
        (v.fpReason ?? "patrón conocido").slice(0, 90),
      ]),
      styles: { fontSize: 7, cellPadding: 2 },
      headStyles: { fillColor: [100, 116, 139], textColor: [255, 255, 255], fontSize: 7 },
      columnStyles: { 1: { cellWidth: 20 }, 2: { cellWidth: 30 }, 3: { cellWidth: 75 } },
    });
  }

  // ── Footer ──
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      "EATHERIA Security Platform — Estándares: OWASP Top 10, CWE Top 25, NIST SP 800-53",
      14,
      pageH - 8
    );
    doc.text(`Página ${i}/${pageCount}`, pageW - 14, pageH - 8, { align: "right" });
  }

  return Buffer.from(doc.output("arraybuffer"));
}

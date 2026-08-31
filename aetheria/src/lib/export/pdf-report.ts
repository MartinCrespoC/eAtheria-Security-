"use client";

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

interface ExportVuln {
  severity: string;
  title: string;
  category: string;
  cweId: string | null;
  owaspTop10: string | null;
  filePath: string | null;
  lineStart: number | null;
  confidence: string;
  smartFix: string | null;
  fixExplanation: string | null;
  isFalsePositive: boolean;
}

interface ExportAnalysis {
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
  inputTokens: number | bigint;
  outputTokens: number | bigint;
  createdAt: string | Date;
  appVersion: {
    version: string;
    application: { name: string };
  };
  vulnerabilities: ExportVuln[];
}

const SEV_COLORS: Record<string, [number, number, number]> = {
  CRITICAL: [220, 38, 38],
  HIGH: [234, 88, 12],
  MEDIUM: [217, 119, 6],
  LOW: [37, 99, 235],
  INFO: [100, 116, 139],
};

export function exportPdfReport(analysis: ExportAnalysis) {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();

  // Header
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

  // App info
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
  doc.text(`Fecha: ${new Date(analysis.createdAt).toLocaleString("es-ES")}  |  Estado: ${analysis.status}`, 14, y);
  y += 10;

  // Summary box
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

  // Vulnerabilities table
  const vulns = analysis.vulnerabilities.filter((v) => !v.isFalsePositive);
  if (vulns.length > 0) {
    doc.setFontSize(11);
    doc.setTextColor(30, 41, 59);
    doc.text(`Vulnerabilidades (${vulns.length})`, 14, y);
    y += 4;

    autoTable(doc, {
      startY: y,
      head: [["Sev", "Título", "CWE", "OWASP", "Archivo", "Confianza"]],
      body: vulns.map((v) => [
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
  }

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      "EATHERIA Security Platform — Estándares: OWASP Top 10, CWE Top 25, NIST SP 800-53",
      14,
      doc.internal.pageSize.getHeight() - 8
    );
    doc.text(`Página ${i}/${pageCount}`, pageW - 14, doc.internal.pageSize.getHeight() - 8, { align: "right" });
  }

  const fileName = `EATHERIA_Report_${analysis.appVersion.application.name.replace(/\s+/g, "_")}_v${analysis.appVersion.version}_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(fileName);
}

"use client";

import ExcelJS from "exceljs";

interface ExportVuln {
  severity: string;
  title: string;
  description: string;
  category: string;
  cweId: string | null;
  cveId: string | null;
  owaspTop10: string | null;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  confidence: string;
  smartFix: string | null;
  fixExplanation: string | null;
  isFalsePositive: boolean;
  aiValidated: boolean;
  status: string;
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

export async function exportExcelReport(analysis: ExportAnalysis) {
  const wb = new ExcelJS.Workbook();
  wb.creator = "EATHERIA Security";
  wb.created = new Date();

  // Sheet 1: Resumen
  const scanTypes = Array.isArray(analysis.scanTypes) ? analysis.scanTypes.join(", ") : "";
  const wsSummary = wb.addWorksheet("Resumen");
  wsSummary.columns = [{ width: 22 }, { width: 50 }];
  wsSummary.addRows([
    ["EATHERIA Security - Reporte de Análisis"],
    [],
    ["Aplicación", analysis.appVersion.application.name],
    ["Versión", analysis.appVersion.version],
    ["Estado", analysis.status],
    ["Tipos de Escaneo", scanTypes],
    ["Fecha", new Date(analysis.createdAt).toLocaleString("es-ES")],
    ["Duración (s)", analysis.duration ?? "N/A"],
    [],
    ["Métricas de Severidad"],
    ["Críticas", analysis.criticalCount],
    ["Altas", analysis.highCount],
    ["Medias", analysis.mediumCount],
    ["Bajas", analysis.lowCount],
    ["Info", analysis.infoCount],
    ["Total Issues", analysis.totalIssues],
    ["Falsos Positivos", analysis.falsePositives],
    [],
    ["Tokens IA"],
    ["Input Tokens", Number(analysis.inputTokens)],
    ["Output Tokens", Number(analysis.outputTokens)],
  ]);
  wsSummary.getRow(1).font = { bold: true, size: 14 };
  wsSummary.getRow(10).font = { bold: true };
  wsSummary.getRow(19).font = { bold: true };

  // Sheet 2: Vulnerabilidades
  const wsVulns = wb.addWorksheet("Vulnerabilidades");
  wsVulns.columns = [
    { header: "Severidad", width: 10 },
    { header: "Título", width: 40 },
    { header: "Descripción", width: 60 },
    { header: "Categoría", width: 18 },
    { header: "CWE", width: 10 },
    { header: "CVE", width: 14 },
    { header: "OWASP", width: 12 },
    { header: "Archivo", width: 35 },
    { header: "Línea Inicio", width: 8 },
    { header: "Línea Fin", width: 8 },
    { header: "Confianza", width: 10 },
    { header: "Smart Fix", width: 50 },
    { header: "Explicación Fix", width: 50 },
    { header: "Falso Positivo", width: 12 },
    { header: "Validado IA", width: 10 },
    { header: "Estado", width: 10 },
  ];
  wsVulns.getRow(1).font = { bold: true };
  wsVulns.addRows(
    analysis.vulnerabilities.map((v) => [
      v.severity,
      v.title,
      v.description,
      v.category,
      v.cweId || "",
      v.cveId || "",
      v.owaspTop10 || "",
      v.filePath || "",
      v.lineStart ?? "",
      v.lineEnd ?? "",
      v.confidence,
      v.smartFix || "",
      v.fixExplanation || "",
      v.isFalsePositive ? "SÍ" : "NO",
      v.aiValidated ? "SÍ" : "NO",
      v.status,
    ])
  );

  // Sheet 3: SBOM placeholder (if available in future)
  const wsSbom = wb.addWorksheet("SBOM");
  wsSbom.columns = [{ width: 60 }];
  wsSbom.addRows([
    ["SBOM - Software Bill of Materials"],
    [],
    ["Formato: CycloneDX"],
    ["Nota: Los datos SBOM se incluyen cuando el análisis SCA está habilitado."],
  ]);

  const fileName = `EATHERIA_Report_${analysis.appVersion.application.name.replace(/\s+/g, "_")}_v${analysis.appVersion.version}_${new Date().toISOString().slice(0, 10)}.xlsx`;

  const buffer = await wb.xlsx.writeBuffer();
  const blob = new Blob([buffer], {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

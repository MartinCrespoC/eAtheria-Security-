import { prisma } from "@/lib/db";
import { isSafeExternalUrl } from "@/lib/security/url-guard";
import { runSastAnalysis, scoreFileRisk, type ScoredFile } from "@/lib/analysis/sast-engine";
import { runScaAnalysis, parseDependencies } from "@/lib/analysis/sca-engine";
import { runDastAnalysis } from "@/lib/analysis/dast-engine";
import { generateSbomJson } from "@/lib/analysis/sbom-generator";
import { falsePositiveDetector } from "@/lib/analysis/false-positive-detector";
import {
  verifyFindingWithAi,
  flushAiVerifierCache,
  type AiChatFn,
} from "@/lib/analysis/ai-verifier";
import { scanProgressStore } from "@/lib/analysis/scan-progress";
import { buildFixPrompt } from "@/lib/analysis/scan-prompt-builder";
import { generateWithGemini } from "@/lib/ai";
import { validateGeneratedFix } from "@/lib/ai/prompt-guard";
import { runTaintAnalysis, type TaintRulesBundle } from "@/lib/analysis/engines/taint-engine";
import { runSecretsDetection, type DbSecretPattern } from "@/lib/analysis/engines/secrets-engine";
import { runIacAnalysis, type DbIacRule } from "@/lib/analysis/engines/iac-engine";
import { runHeuristicChecks } from "@/lib/analysis/engines/heuristic-engine";
import { generateFingerprint, computeDelta } from "@/lib/analysis/engines/delta-engine";
import { buildKnowledgeIndex, getKnowledgeForFinding, type KnowledgeIndex } from "@/lib/knowledge";
import { notifyScanStarted, notifyScanCompleted, notifyScanFailed } from "@/lib/messaging/company-notifier";
import type { ScanLevel } from "@/lib/analysis/scan-knowledge";
import {
  scanForSecurityGuidance,
  buildPolicyContext,
  buildThreatModelPrompt,
  parseThreatModel,
  buildThreatModelContext,
  inferRepoCapabilities,
  buildAttackPathPrompt,
  parseAttackPathResponse,
  toVulnerabilityUpdate,
  buildValidationPrompt,
  parseValidationResponse,
  toValidationUpdate,
  type ThreatModelData,
} from "@/lib/methodology";
import * as fs from "fs";
import * as path from "path";

export interface SourceCodeBundle {
  code: string;
  depFiles: { filename: string; content: string }[];
}

// Library/vendor directories excluded from SAST — handled by SCA (OSV)
const EXCLUDED_DIRS = new Set([
  "node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages",
  "vendor", "target", "Pods", ".gradle", ".m2", "bower_components",
  ".terraform", "dist", "build", "out", ".next", "coverage",
  ".cache", "pkg", "bin", "obj", ".svn", ".hg",
]);

/**
 * Tolerantly parse AI JSON responses.
 * Models frequently wrap JSON in markdown fences (```json ... ```) or add
 * surrounding prose, which breaks a raw JSON.parse. This strips fences and,
 * as a fallback, extracts the first {...} block. Mirrors the parsing already
 * used by the SAST/DAST engines so fix generation behaves consistently.
 */
function parseAiJson<T = Record<string, unknown>>(text: string | null | undefined): T | null {
  if (!text) return null;
  const cleaned = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start !== -1 && end > start) {
      try {
        return JSON.parse(cleaned.slice(start, end + 1)) as T;
      } catch {
        return null;
      }
    }
    return null;
  }
}

export async function triggerAnalysis(analysisId: string) {
  const startTime = Date.now();

  // Hoisted so the catch block can notify about failures
  let failCompanyId: string | null = null;
  let failAppName = "";
  let failVersion: string | undefined;

  // Initialize false positive detector (loads patterns from DB)
  await falsePositiveDetector.initialize();

  await prisma.analysis.update({
    where: { id: analysisId },
    data: { status: "INITIALIZING", startedAt: new Date() },
  });

  try {
    // Load analysis with version and app details
    const analysis = await prisma.analysis.findUnique({
      where: { id: analysisId },
      include: {
        appVersion: {
          include: { application: { select: { id: true, name: true, companyId: true, language: true, repoUrl: true } } },
        },
      },
    });

    if (!analysis) throw new Error("Analysis not found");

    const companyId = analysis.appVersion.application.companyId;
    const language = analysis.appVersion.application.language || "unknown";
    const scanTypes = Array.isArray(analysis.scanTypes) ? analysis.scanTypes as string[] : ["SAST"];
    const scanLevel = ((analysis as Record<string, unknown>).scanLevel || "STATIC") as ScanLevel;

    // Capture context for failure notification
    failCompanyId = companyId;
    failAppName = analysis.appVersion.application.name;
    failVersion = analysis.appVersion.version;

    // Initialize progress tracking
    scanProgressStore.init(analysisId, scanTypes, scanLevel);
    scanProgressStore.update(analysisId, (s) => { s.status = "running"; });
    scanProgressStore.log(analysisId, "info", `Análisis iniciado — Nivel: ${scanLevel === "STATIC" ? "Estático (L1)" : scanLevel === "LIGHTWEIGHT" ? "Ligero (L2)" : "Profundo (L3)"}`);
    scanProgressStore.log(analysisId, "info", `Motores activos: ${scanTypes.join(", ")}`);

    // Token/cost accumulator for this scan
    const scanTokens = { input: 0, output: 0, cost: 0 };

    // Notify messaging channels (fire-and-forget, never blocks the scan)
    if (companyId) {
      notifyScanStarted(companyId, {
        appName: analysis.appVersion.application.name,
        version: analysis.appVersion.version,
        scanTypes,
      }).catch(() => {});
    }

    // === DISCOVERY PHASE ===
    scanProgressStore.updateStep(analysisId, "discovery", { status: "running", progress: 10 });
    scanProgressStore.log(analysisId, "info", "Fase 1: Descubrimiento de archivos fuente...");

    const sourceCode = await gatherSourceCode(analysis.appVersion.id, analysis.appVersion.sourceUrl);

    // Count files and detect languages
    const fileStats = await analyzeFileStats(analysis.appVersion.id);
    scanProgressStore.update(analysisId, (s) => {
      s.stats.filesDiscovered = fileStats.totalFiles;
      s.stats.languagesDetected = fileStats.languages;
      s.stats.linesOfCode = fileStats.linesOfCode;
    });
    scanProgressStore.log(analysisId, "success", `${fileStats.totalFiles} archivos descubiertos (${fileStats.linesOfCode.toLocaleString()} LOC)`);
    scanProgressStore.log(analysisId, "info", `Lenguajes detectados: ${fileStats.languages.join(", ") || language}`);
    scanProgressStore.updateStep(analysisId, "discovery", { status: "completed", progress: 100, metadata: { files: fileStats.totalFiles, loc: fileStats.linesOfCode } });

    // === SECURITY GUIDANCE (SECURITY.md resolution) ===
    let securityPolicyContext = "";
    const uploadDirGuidance = path.join(process.cwd(), "uploads", analysis.appVersion.id);
    try {
      const guidance = scanForSecurityGuidance(uploadDirGuidance);
      securityPolicyContext = buildPolicyContext(guidance);
      if (guidance.hasPolicy) {
        scanProgressStore.log(analysisId, "info", `SECURITY.md detectado en: ${guidance.sources.map((s) => path.basename(path.dirname(s))).join(", ")}`);
      } else {
        scanProgressStore.log(analysisId, "info", "Sin SECURITY.md — aplicando trust boundaries por defecto");
      }
    } catch (guidanceErr) {
      console.error("Security guidance resolution failed (non-fatal):", guidanceErr);
    }

    // === THREAT MODEL (LIGHTWEIGHT + DEEP only) ===
    let threatModelContext = "";
    let threatModelData: ThreatModelData | null = null;
    if (scanLevel !== "STATIC") {
      scanProgressStore.log(analysisId, "info", "Fase: Generación de modelo de amenazas...");
      try {
        const allFilesForTm = await walkDir(uploadDirGuidance);
        const repoCapabilities = inferRepoCapabilities(allFilesForTm.map((f) => path.relative(uploadDirGuidance, f)));
        const tmPrompt = buildThreatModelPrompt({
          languages: fileStats.languages,
          frameworks: repoCapabilities.frameworks || [],
          fileStructure: allFilesForTm.slice(0, 100).map((f) => path.relative(uploadDirGuidance, f)).join("\n"),
          dependencies: sourceCode.depFiles.map((d) => d.filename),
        });

        const tmResponse = await generateWithGemini(tmPrompt, { temperature: 0.2, maxOutputTokens: 3000, companyId });
        scanTokens.input += tmResponse?.inputTokens ?? 0;
        scanTokens.output += tmResponse?.outputTokens ?? 0;
        scanTokens.cost += tmResponse?.cost ?? 0;
        threatModelData = parseThreatModel(tmResponse?.text || "");

        if (threatModelData) {
          threatModelContext = buildThreatModelContext(threatModelData);
          // Persist threat model
          await prisma.threatModel.create({
            data: {
              analysisId,
              content: threatModelData.content,
              actors: threatModelData.actors as never,
              boundaries: threatModelData.boundaries as never,
              assets: threatModelData.assets as never,
              threats: threatModelData.threats as never,
            },
          });
          scanProgressStore.log(analysisId, "success", `Modelo de amenazas: ${threatModelData.actors.length} actores, ${threatModelData.threats.length} amenazas identificadas`);
        }
      } catch (tmErr) {
        console.error("Threat model generation failed (non-fatal):", tmErr);
        scanProgressStore.log(analysisId, "warning", "Modelo de amenazas: error no crítico");
      }
    }

    // === L1: DETERMINISTIC ENGINES (Taint + Secrets + IaC) ===
    let totalVulns = 0;
    const deterministicFindings: { fingerprint: string; cweId: string; filePath: string }[] = [];

    // Load BugHunter knowledge index (one DB load for entire scan)
    let knowledgeIndex: KnowledgeIndex | undefined;
    try {
      knowledgeIndex = await buildKnowledgeIndex();
      scanProgressStore.log(analysisId, "info", `Knowledge: ${knowledgeIndex.allSkills.length} skills BugHunter cargados`);
    } catch (kErr) {
      console.error("Knowledge index load failed (non-fatal):", kErr);
      scanProgressStore.log(analysisId, "warning", "Knowledge: no se pudo cargar índice de conocimiento");
    }

    // Load all rules from DB (dynamic, not hardcoded)
    scanProgressStore.log(analysisId, "info", "Cargando reglas de seguridad desde base de datos...");
    const [dbSources, dbSinks, dbSanitizers, dbSecretPatterns, dbIacRules] = await Promise.all([
      prisma.taintSource.findMany({ where: { isActive: true }, select: { language: true, pattern: true } }),
      prisma.taintSink.findMany({ where: { isActive: true }, select: { language: true, pattern: true, cwe: true, category: true, severity: true, owasp2021: true } }),
      prisma.taintSanitizer.findMany({ where: { isActive: true }, select: { language: true, pattern: true } }),
      prisma.secretPattern.findMany({ where: { isActive: true }, select: { ruleId: true, name: true, regex: true, severity: true, cwe: true, description: true } }),
      prisma.iacRule.findMany({ where: { isActive: true }, select: { ruleId: true, name: true, pattern: true, severity: true, cwe: true, category: true, description: true, fileTypes: true, framework: true } }),
    ]);

    const taintRules: TaintRulesBundle = { sources: dbSources, sinks: dbSinks, sanitizers: dbSanitizers };
    const secretPatterns: DbSecretPattern[] = dbSecretPatterns;
    const iacRules: DbIacRule[] = dbIacRules as unknown as DbIacRule[];

    // Map numeric confidence to enum
    const toConfidence = (n: number): "HIGH" | "MEDIUM" | "LOW" => n >= 85 ? "HIGH" : n >= 65 ? "MEDIUM" : "LOW";

    // Test files (*.test.*, *.spec.*, __tests__/) get severity downgraded one
    // notch: hardcoded fixture creds etc. matter less than production code,
    // and competitors inflate reports by scoring test code at full severity.
    const isTestFile = (p: string) => /\.(test|spec)\.[a-z0-9]+$/i.test(p) || p.includes("__tests__/");
    const downgradeSeverity = <T extends string>(s: T): T =>
      (s === "CRITICAL" ? "HIGH" : s === "HIGH" ? "MEDIUM" : s === "MEDIUM" ? "LOW" : s) as T;

    scanProgressStore.log(analysisId, "info", `Reglas DB: ${dbSources.length} sources, ${dbSinks.length} sinks, ${dbSanitizers.length} sanitizers, ${dbSecretPatterns.length} secrets, ${dbIacRules.length} IaC`);

    // Run deterministic engines per file
    const uploadDir = path.join(process.cwd(), "uploads", analysis.appVersion.id);
    let l1Findings = 0;

    try {
      const allFiles = await walkDir(uploadDir);
      const codeExtensions = [".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs", ".kt", ".scala", ".swift", ".pl", ".lua", ".r", ".dart", ".ex", ".exs"];
      const iacExtensions = [".tf", ".yaml", ".yml", ".json"];
      const extToLang: Record<string, string> = { ".ts": "javascript", ".tsx": "javascript", ".js": "javascript", ".jsx": "javascript", ".py": "python", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".rs": "rust", ".kt": "kotlin", ".scala": "scala", ".swift": "swift", ".pl": "perl", ".lua": "lua", ".r": "r", ".dart": "dart", ".ex": "elixir", ".exs": "elixir" };

      scanProgressStore.updateStep(analysisId, "sast", { status: "running", progress: 5 });
      scanProgressStore.log(analysisId, "info", "Fase L1: Motores determinísticos (Taint + Secrets + IaC)...");

      for (const file of allFiles) {
        const ext = path.extname(file).toLowerCase();
        const relPath = path.relative(uploadDir, file);
        let content: string;
        try { content = fs.readFileSync(file, "utf-8"); } catch { continue; }
        if (content.length > 500000) continue; // Skip huge files

        // Taint analysis for code files
        if (codeExtensions.includes(ext)) {
          const lang = extToLang[ext] || "javascript";
          const taintFindings = runTaintAnalysis(content, relPath, lang, taintRules);
          for (const tf of taintFindings) {
            const fp = generateFingerprint(tf.filePath, tf.cwe, tf.codeSnippet);
            deterministicFindings.push({ fingerprint: fp, cweId: tf.cwe, filePath: tf.filePath });
            await prisma.vulnerability.create({
              data: {
                analysisId,
                title: tf.title,
                description: tf.description,
                severity: (isTestFile(relPath) ? downgradeSeverity(tf.severity) : tf.severity) as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                category: tf.category,
                cweId: tf.cwe,
                owaspTop10: tf.owasp2021,
                filePath: tf.filePath,
                lineStart: tf.lineStart,
                lineEnd: tf.lineEnd,
                codeSnippet: tf.codeSnippet,
                confidence: toConfidence(tf.confidence),
                fingerprint: fp,
                detectionMethod: "TAINT",
              },
            });
            l1Findings++;
          }
        }

        // Secrets detection for ALL text files
        const secretFindings = runSecretsDetection(content, relPath, secretPatterns);
        for (const sf of secretFindings) {
          const fp = generateFingerprint(sf.filePath, sf.cwe, sf.codeSnippet);
          deterministicFindings.push({ fingerprint: fp, cweId: sf.cwe, filePath: sf.filePath });
          await prisma.vulnerability.create({
            data: {
              analysisId,
              title: sf.title,
              description: sf.description,
              severity: (isTestFile(relPath) ? downgradeSeverity(sf.severity) : sf.severity) as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
              category: sf.category,
              cweId: sf.cwe,
              owaspTop10: sf.owasp2021,
              filePath: sf.filePath,
              lineStart: sf.lineStart,
              lineEnd: sf.lineEnd,
              codeSnippet: sf.codeSnippet,
              confidence: toConfidence(sf.confidence),
              fingerprint: fp,
              detectionMethod: "SECRET",
            },
          });
          l1Findings++;
        }

        // Heuristic checks (ReDoS CWE-1333, sensitive logging CWE-200)
        if (codeExtensions.includes(ext)) {
          const heuristicFindings = runHeuristicChecks(content, relPath);
          for (const hf of heuristicFindings) {
            const fp = generateFingerprint(hf.filePath, hf.cwe, hf.codeSnippet);
            deterministicFindings.push({ fingerprint: fp, cweId: hf.cwe, filePath: hf.filePath });
            await prisma.vulnerability.create({
              data: {
                analysisId,
                title: hf.title,
                description: hf.description,
                severity: (isTestFile(relPath) ? downgradeSeverity(hf.severity) : hf.severity) as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                category: hf.category,
                cweId: hf.cwe,
                owaspTop10: hf.owasp2021,
                filePath: hf.filePath,
                lineStart: hf.lineStart,
                lineEnd: hf.lineEnd,
                codeSnippet: hf.codeSnippet,
                confidence: toConfidence(hf.confidence),
                fingerprint: fp,
                detectionMethod: "HEURISTIC",
              },
            });
            l1Findings++;
          }
        }

        // IaC scanning for infrastructure files
        if (iacExtensions.includes(ext) || relPath.toLowerCase().includes("dockerfile")) {
          const iacFindings = runIacAnalysis(content, relPath, iacRules);
          for (const iaf of iacFindings) {
            const fp = generateFingerprint(iaf.filePath, iaf.cwe, iaf.codeSnippet);
            deterministicFindings.push({ fingerprint: fp, cweId: iaf.cwe, filePath: iaf.filePath });
            await prisma.vulnerability.create({
              data: {
                analysisId,
                title: iaf.title,
                description: iaf.description,
                severity: iaf.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                category: iaf.category,
                cweId: iaf.cwe,
                owaspTop10: iaf.owasp2021,
                filePath: iaf.filePath,
                lineStart: iaf.lineStart,
                lineEnd: iaf.lineEnd,
                codeSnippet: iaf.codeSnippet,
                confidence: toConfidence(iaf.confidence),
                fingerprint: fp,
                detectionMethod: "IAC",
              },
            });
            l1Findings++;
          }
        }
      }

      totalVulns += l1Findings;
      scanProgressStore.update(analysisId, (s) => { s.stats.vulnerabilitiesFound += l1Findings; });
      scanProgressStore.log(analysisId, "success", `L1 Determinístico completado: ${l1Findings} hallazgos (Taint + Secrets + IaC)`);
      scanProgressStore.updateStep(analysisId, "sast", { progress: 20 });
    } catch (l1Err) {
      console.error("L1 deterministic engines error:", l1Err);
      scanProgressStore.log(analysisId, "warning", "L1: Error parcial en motores determinísticos");
    }

    // === L2: AI SAST (per-file, token-optimized, knowledge-enriched) ===
    if (scanTypes.includes("SAST") && sourceCode.code) {
      scanProgressStore.updateStep(analysisId, "sast", { status: "running", progress: 30 });
      scanProgressStore.log(analysisId, "info", "Fase L2: Análisis SAST con IA (por archivo, optimizado en tokens)...");
      scanProgressStore.log(analysisId, "debug", `Metodología: ${scanLevel === "DEEP" ? "Análisis de flujo de datos entre archivos" : scanLevel === "LIGHTWEIGHT" ? "Análisis de flujo intra-archivo" : "Coincidencia de patrones por archivo"}`);

      // Build scored file list from upload directory
      const scoredFiles: ScoredFile[] = [];
      const uploadDirSast = path.join(process.cwd(), "uploads", analysis.appVersion.id);
      const codeExtensionsSast = [".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs", ".kt", ".scala", ".swift"];
      const extToLangSast: Record<string, string> = { ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".py": "python", ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".rs": "rust", ".kt": "kotlin", ".scala": "scala", ".swift": "swift" };

      try {
        const allFilesSast = await walkDir(uploadDirSast);
        for (const file of allFilesSast) {
          const ext = path.extname(file).toLowerCase();
          if (!codeExtensionsSast.includes(ext)) continue;
          let content: string;
          try { content = fs.readFileSync(file, "utf-8"); } catch { continue; }
          if (content.length > 200000) continue; // Skip very large files
          const relPath = path.relative(uploadDirSast, file);
          const fileLang = extToLangSast[ext] || "javascript";
          scoredFiles.push({ path: relPath, content, language: fileLang, riskScore: scoreFileRisk(content, relPath) });
        }
      } catch {
        // Fallback: use concatenated source as single file
        scoredFiles.push({ path: "source.ts", content: sourceCode.code, language: language.toLowerCase(), riskScore: 50 });
      }

      scanProgressStore.log(analysisId, "info", `${scoredFiles.length} archivos priorizados por riesgo para análisis IA`);
      scanProgressStore.updateStep(analysisId, "sast", { progress: 50 });

      const sastResult = await runSastAnalysis(analysisId, scoredFiles, language, companyId, scanLevel, knowledgeIndex);
      totalVulns += sastResult.summary.totalIssues;
      scanTokens.input += sastResult.tokenUsage.inputTokens;
      scanTokens.output += sastResult.tokenUsage.outputTokens;
      scanTokens.cost += sastResult.tokenUsage.cost;

      scanProgressStore.update(analysisId, (s) => {
        s.stats.vulnerabilitiesFound += sastResult.summary.totalIssues;
        s.stats.filesAnalyzed = sastResult.filesAnalyzed;
      });
      scanProgressStore.log(analysisId, "success", `SAST IA completado: ${sastResult.summary.totalIssues} hallazgos (${sastResult.filesAnalyzed} archivos analizados, ${sastResult.filesSkipped} omitidos por presupuesto)`);
      scanProgressStore.updateStep(analysisId, "sast", { status: "completed", progress: 100, metadata: { findings: sastResult.summary.totalIssues + l1Findings, files: sastResult.filesAnalyzed } });
    } else if (scanTypes.includes("SAST")) {
      scanProgressStore.updateStep(analysisId, "sast", { status: "skipped", progress: 0 });
      scanProgressStore.log(analysisId, "warning", "SAST omitido: no se encontró código fuente");
    }

    // Run SCA if enabled and dependencies found
    if (scanTypes.includes("SCA") && sourceCode.depFiles.length > 0) {
      scanProgressStore.updateStep(analysisId, "sca", { status: "running", progress: 10 });
      scanProgressStore.log(analysisId, "info", "Fase 3: Análisis de composición de software (SCA)...");
      scanProgressStore.log(analysisId, "info", `Archivos de dependencias: ${sourceCode.depFiles.map((d) => d.filename).join(", ")}`);

      const allDeps: { name: string; version: string; ecosystem: string }[] = [];
      for (const depFile of sourceCode.depFiles) {
        const parsed = parseDependencies(depFile.content, depFile.filename);
        allDeps.push(...parsed);
      }

      scanProgressStore.update(analysisId, (s) => { s.stats.dependenciesFound = allDeps.length; });
      scanProgressStore.log(analysisId, "info", `${allDeps.length} dependencias identificadas — consultando bases de datos de vulnerabilidades (OSV/NVD)...`);
      scanProgressStore.updateStep(analysisId, "sca", { progress: 40 });

      if (allDeps.length > 0) {
        const scaVulns = await runScaAnalysis(analysisId, allDeps);
        totalVulns += scaVulns.length;

        scanProgressStore.update(analysisId, (s) => {
          s.stats.vulnerabilitiesFound += scaVulns.length;
        });
        scanProgressStore.log(analysisId, "success", `SCA completado: ${scaVulns.length} vulnerabilidades en dependencias`);
        scanProgressStore.updateStep(analysisId, "sca", { status: "completed", progress: 100, metadata: { deps: allDeps.length, vulns: scaVulns.length } });

        // Generate SBOM
        scanProgressStore.updateStep(analysisId, "sbom", { status: "running", progress: 50 });
        scanProgressStore.log(analysisId, "info", "Generando SBOM (CycloneDX)...");
        try {
          const sbomData = generateSbomJson(
            allDeps,
            analysis.appVersion.application.repoUrl || "application",
            analysis.appVersion.version
          );
          await prisma.analysis.update({
            where: { id: analysisId },
            data: { sbomGenerated: true, sbomFormat: "CycloneDX", sbomData },
          });
          scanProgressStore.log(analysisId, "success", `SBOM generado: ${allDeps.length} componentes inventariados`);
          scanProgressStore.updateStep(analysisId, "sbom", { status: "completed", progress: 100 });
        } catch (sbomErr) {
          console.error("SBOM generation failed (non-fatal):", sbomErr);
          scanProgressStore.log(analysisId, "warning", "SBOM: error no crítico durante generación");
          scanProgressStore.updateStep(analysisId, "sbom", { status: "error", progress: 100 });
        }
      }
    } else if (scanTypes.includes("SCA")) {
      scanProgressStore.updateStep(analysisId, "sca", { status: "skipped", progress: 0 });
      scanProgressStore.updateStep(analysisId, "sbom", { status: "skipped", progress: 0 });
      scanProgressStore.log(analysisId, "warning", "SCA omitido: no se encontraron archivos de dependencias");
    }

    // Run DAST if enabled
    if (scanTypes.includes("DAST")) {
      const targetUrl = analysis.appVersion.sourceUrl || analysis.appVersion.application.repoUrl;
      if (targetUrl && isSafeExternalUrl(targetUrl)) {
        scanProgressStore.updateStep(analysisId, "dast", { status: "running", progress: 10 });
        scanProgressStore.log(analysisId, "info", "Análisis dinámico (DAST) en ejecución...");
        const dastResult = await runDastAnalysis(analysisId, targetUrl, companyId, knowledgeIndex);
        totalVulns += dastResult.summary.totalIssues;
        scanTokens.input += dastResult.tokenUsage.inputTokens;
        scanTokens.output += dastResult.tokenUsage.outputTokens;
        scanTokens.cost += dastResult.tokenUsage.cost;
        scanProgressStore.log(analysisId, "success", `DAST completado: ${dastResult.summary.totalIssues} hallazgos`);
        scanProgressStore.updateStep(analysisId, "dast", { status: "completed", progress: 100 });
      } else {
        scanProgressStore.updateStep(analysisId, "dast", { status: "skipped", progress: 0 });
        scanProgressStore.log(analysisId, "warning", "DAST omitido: se requiere una URL objetivo válida");
      }
    }

    // === DEDUP: collapse identical findings (same CWE + file + line + title) ===
    // Engines can emit the same issue multiple times: taint reaching the same
    // sink line via several propagation paths, overlapping TAINT/AI hits, etc.
    // Runs before FP detection and AI triage so neither wastes budget on dupes.
    // SCA rows (no file/line) survive because their titles differ per CVE.
    try {
      const allRows = await prisma.vulnerability.findMany({
        where: { analysisId },
        select: { id: true, cweId: true, filePath: true, lineStart: true, title: true },
        orderBy: { createdAt: "asc" },
      });
      const seenKeys = new Set<string>();
      const dupeIds: string[] = [];
      for (const r of allRows) {
        const key = `${r.cweId || ""}|${r.filePath || ""}|${r.lineStart ?? 0}|${r.title}`;
        if (seenKeys.has(key)) dupeIds.push(r.id);
        else seenKeys.add(key);
      }
      if (dupeIds.length > 0) {
        await prisma.vulnerability.deleteMany({ where: { id: { in: dupeIds } } });
        totalVulns -= dupeIds.length;
        scanProgressStore.log(analysisId, "info", `Dedup: ${dupeIds.length} hallazgos duplicados consolidados`);
      }
    } catch (dedupErr) {
      console.error("Dedup failed (non-fatal):", dedupErr);
    }

    // === FALSE POSITIVE DETECTION ===
    await prisma.analysis.update({
      where: { id: analysisId },
      data: { status: "VALIDATING" },
    });

    scanProgressStore.updateStep(analysisId, "fp-detection", { status: "running", progress: 10 });
    scanProgressStore.log(analysisId, "info", "Fase: Validación de falsos positivos...");
    scanProgressStore.log(analysisId, "info", "Cruzando hallazgos con base de conocimiento de patrones seguros (195+ reglas)");

    const allVulns = await prisma.vulnerability.findMany({
      where: { analysisId },
      select: { id: true, cweId: true, codeSnippet: true, filePath: true, lineStart: true, severity: true, title: true, description: true, smartFix: true },
    });

    let fpCount = 0;
    const totalToCheck = allVulns.filter((v) => v.cweId).length;
    let checked = 0;

    for (const vuln of allVulns) {
      if (!vuln.cweId) continue;
      checked++;
      const matchText = [
        vuln.codeSnippet || "",
        vuln.title || "",
        vuln.description || "",
        vuln.smartFix || "",
      ].join("\n");
      const fpResult = await falsePositiveDetector.checkVulnerability({
        cweId: vuln.cweId,
        code: matchText,
        language: language.toLowerCase(),
        line: vuln.lineStart || 0,
        file: vuln.filePath || "",
        severity: vuln.severity,
        scanLevel,
        codeSnippet: vuln.codeSnippet || undefined,
      });
      if (fpResult.isFalsePositive) {
        const mp = fpResult.matchedPattern;
        // Provenance tag for ingested knowledge (gitleaks/cwe/semgrep/juliet).
        const provenance =
          mp?.source && mp.source !== "builtin"
            ? ` [source: ${mp.source}${mp.sourceRuleId ? `#${mp.sourceRuleId}` : ""}]`
            : "";
        await prisma.vulnerability.update({
          where: { id: vuln.id },
          data: {
            isFalsePositive: true,
            fpReason: mp
              ? `${mp.description}: ${mp.reason}${provenance}`
              : "Matched false positive pattern",
          },
        });
        fpCount++;
        scanProgressStore.log(analysisId, "info", `FP detectado: ${vuln.title} (${vuln.cweId}) — ${fpResult.matchedPattern?.description || "patrón conocido"}`);
      }
      // Update progress periodically
      if (checked % 5 === 0 || checked === totalToCheck) {
        const pct = Math.round((checked / Math.max(totalToCheck, 1)) * 100);
        scanProgressStore.updateStep(analysisId, "fp-detection", { progress: pct });
      }
    }

    scanProgressStore.update(analysisId, (s) => { s.stats.falsePositivesDetected = fpCount; });
    scanProgressStore.log(analysisId, "success", `Validación FP completada: ${fpCount} falsos positivos eliminados de ${totalToCheck} hallazgos`);
    scanProgressStore.updateStep(analysisId, "fp-detection", { status: "completed", progress: 100, metadata: { checked: totalToCheck, fp: fpCount } });

    // === AI TRIAGE (opt-in: analysis.aiValidation, default ON) ===
    // LLM re-review of kept findings with full file + project context.
    // Rules learned from the CVE benchmark: never auto-delete on model
    // confidence alone; dismissals require a citable evidenceLine verified
    // inside the file (enforced by verifyFindingWithAi); every verdict is
    // persisted (aiValidated/aiConfidence/fpReason) for human audit.
    if (analysis.aiValidation !== false) {
      try {
        const keptForAi = await prisma.vulnerability.findMany({
          where: { analysisId, isFalsePositive: false, cweId: { not: null } },
          select: {
            id: true, cweId: true, category: true, severity: true, title: true,
            filePath: true, lineStart: true, codeSnippet: true, description: true, detectionMethod: true,
          },
          take: 50,
        });

        if (keptForAi.length > 0) {
          scanProgressStore.log(analysisId, "info", `Fase: Triage AI de ${keptForAi.length} hallazgos (verificación con contexto de proyecto)...`);

          // Project files for caller/cross-file evidence (capped).
          const projectFiles = new Map<string, string>();
          const codeExt = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php", ".cs"]);
          const allPaths = await walkDir(uploadDirGuidance);
          for (const p of allPaths) {
            if (projectFiles.size >= 400) break;
            if (!codeExt.has(path.extname(p).toLowerCase()) || p.endsWith(".d.ts")) continue;
            try {
              const content = fs.readFileSync(p, "utf8");
              if (content.length < 300_000) projectFiles.set(path.relative(uploadDirGuidance, p), content);
            } catch { /* skip unreadable */ }
          }

          const chat: AiChatFn = async ({ system, user, maxTokens }) => {
            const res = await generateWithGemini(user, {
              systemInstruction: system,
              temperature: 0,
              maxOutputTokens: maxTokens ?? 3000,
              companyId,
            });
            scanTokens.input += res?.inputTokens ?? 0;
            scanTokens.output += res?.outputTokens ?? 0;
            scanTokens.cost += res?.cost ?? 0;
            return res?.text ?? "";
          };

          let aiFp = 0, aiTp = 0, aiUncertain = 0, aiChecked = 0;
          let cursor = 0;
          const workers = Array.from({ length: 4 }, async () => {
            while (cursor < keptForAi.length) {
              const vuln = keptForAi[cursor++];
              const absPath = vuln.filePath ? path.join(uploadDirGuidance, vuln.filePath) : "";
              let fileContent: string | undefined;
              try {
                if (absPath && fs.existsSync(absPath)) fileContent = fs.readFileSync(absPath, "utf8");
              } catch { /* skip */ }
              const verdict = await verifyFindingWithAi(
                {
                  cweId: vuln.cweId ?? "CWE-?",
                  category: vuln.category ?? vuln.title,
                  severity: vuln.severity,
                  title: vuln.title,
                  file: vuln.filePath ?? "",
                  line: vuln.lineStart ?? 0,
                  snippet: (vuln.codeSnippet ?? "").slice(0, 2000),
                  source: vuln.detectionMethod ?? "TAINT",
                  taintPath: [(vuln.description ?? "").slice(0, 500)],
                  fileContent,
                  projectFiles,
                },
                chat,
              );
              aiChecked++;
              if (!verdict) continue;
              if (verdict.verdict === "fp") {
                aiFp++;
                await prisma.vulnerability.update({
                  where: { id: vuln.id },
                  data: {
                    isFalsePositive: true,
                    fpReason: `AI triage (${verdict.confidence}%): ${verdict.reason}`,
                    aiValidated: true,
                    aiConfidence: verdict.confidence,
                  },
                });
                scanProgressStore.log(analysisId, "info", `AI triage FP: ${vuln.title} (${vuln.cweId}) — ${verdict.reason.slice(0, 120)}`);
              } else {
                if (verdict.verdict === "tp") aiTp++; else aiUncertain++;
                await prisma.vulnerability.update({
                  where: { id: vuln.id },
                  data: { aiValidated: true, aiConfidence: verdict.confidence },
                });
              }
            }
          });
          await Promise.all(workers);
          flushAiVerifierCache();

          scanProgressStore.update(analysisId, (s) => { s.stats.falsePositivesDetected += aiFp; });
          scanProgressStore.log(
            analysisId,
            "success",
            `Triage AI completado: ${aiFp} probables FP · ${aiTp} confirmados · ${aiUncertain} inciertos (de ${aiChecked})`,
          );
        }
      } catch (aiTriageErr) {
        console.error("AI triage failed (non-fatal):", aiTriageErr);
        scanProgressStore.log(analysisId, "warning", "Triage AI no disponible — se conserva el resultado determinista");
      }
    }

    // === ATTACK-PATH ANALYSIS + VALIDATION (LIGHTWEIGHT + DEEP only) ===
    if (scanLevel !== "STATIC") {
      const apSeverities = (scanLevel === "DEEP"
        ? ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        : ["CRITICAL", "HIGH", "MEDIUM"]) as Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO">;

      const apCandidates = await prisma.vulnerability.findMany({
        where: {
          analysisId,
          severity: { in: apSeverities },
          isFalsePositive: false,
        },
        select: {
          id: true,
          title: true,
          description: true,
          severity: true,
          cweId: true,
          category: true,
          filePath: true,
          lineStart: true,
          codeSnippet: true,
        },
        take: scanLevel === "DEEP" ? 40 : 20,
      });

      if (apCandidates.length > 0) {
        scanProgressStore.log(analysisId, "info", `Fase: Análisis de ruta de ataque para ${apCandidates.length} hallazgos...`);
        let apEnriched = 0;

        for (let i = 0; i < apCandidates.length; i++) {
          const vuln = apCandidates[i];
          try {
            // Build attack-path prompt with threat model context
            const apPrompt = buildAttackPathPrompt(
              {
                title: vuln.title,
                description: vuln.description,
                severity: vuln.severity,
                cweId: vuln.cweId,
                category: vuln.category || undefined,
                filePath: vuln.filePath || undefined,
                lineStart: vuln.lineStart || undefined,
                codeSnippet: vuln.codeSnippet || undefined,
              },
              threatModelContext || undefined,
              securityPolicyContext || undefined
            );

            const apResponse = await generateWithGemini(apPrompt, { temperature: 0.1, maxOutputTokens: 2000, companyId });
            scanTokens.input += apResponse?.inputTokens ?? 0;
            scanTokens.output += apResponse?.outputTokens ?? 0;
            scanTokens.cost += apResponse?.cost ?? 0;
            const apResult = parseAttackPathResponse(apResponse?.text || "");

            if (apResult) {
              const updateData = toVulnerabilityUpdate(apResult);
              await prisma.vulnerability.update({ where: { id: vuln.id }, data: updateData });
              apEnriched++;
            }

            // DEEP scan: also run validation enrichment
            if (scanLevel === "DEEP") {
              const valPrompt = buildValidationPrompt(
                {
                  title: vuln.title,
                  description: vuln.description,
                  cweId: vuln.cweId,
                  filePath: vuln.filePath,
                  lineStart: vuln.lineStart,
                  codeSnippet: vuln.codeSnippet,
                  severity: vuln.severity,
                  category: vuln.category || undefined,
                },
                vuln.codeSnippet || undefined,
                knowledgeIndex ? undefined : undefined
              );

              const valResponse = await generateWithGemini(valPrompt, { temperature: 0.1, maxOutputTokens: 1500, companyId });
              scanTokens.input += valResponse?.inputTokens ?? 0;
              scanTokens.output += valResponse?.outputTokens ?? 0;
              scanTokens.cost += valResponse?.cost ?? 0;
              const valResult = parseValidationResponse(valResponse?.text || "");

              if (valResult) {
                const valUpdate = toValidationUpdate(valResult);
                await prisma.vulnerability.update({ where: { id: vuln.id }, data: valUpdate });
              }
            }
          } catch (apErr) {
            console.error(`Attack-path analysis failed for vuln ${vuln.id}:`, apErr);
          }

          // Progress update
          if ((i + 1) % 5 === 0 || i === apCandidates.length - 1) {
            scanProgressStore.log(analysisId, "info", `Attack-path: ${i + 1}/${apCandidates.length} procesados`);
          }
        }

        scanProgressStore.log(analysisId, "success", `Attack-path completado: ${apEnriched}/${apCandidates.length} hallazgos enriquecidos`);
      }
    }

    // === AI FIX GENERATION (MEDIUM/HIGH/CRITICAL, knowledge-enriched) ===
    const [maxFixesConfig] = await Promise.all([
      prisma.systemConfig.findUnique({ where: { key: "sast_max_fixes" } }),
    ]);
    const maxFixes = parseInt(String(maxFixesConfig?.value ?? "25"), 10);

    const fixableVulns = await prisma.vulnerability.findMany({
      where: {
        analysisId,
        severity: { in: ["CRITICAL", "HIGH", "MEDIUM"] },
        isFalsePositive: false,
        smartFix: null,
        filePath: { not: null },
      },
      take: maxFixes,
    });

    if (fixableVulns.length > 0) {
      scanProgressStore.log(analysisId, "info", `Generando fixes IA para ${fixableVulns.length} vulnerabilidades MEDIUM+...`);
      const uploadDir = path.join(process.cwd(), "uploads", analysis.appVersion.id);
      let fixesGenerated = 0;

      for (let i = 0; i < fixableVulns.length; i++) {
        const vuln = fixableVulns[i];
        try {
          let fileContent = "";
          if (vuln.filePath) {
            const fullPath = path.join(uploadDir, vuln.filePath);
            if (fs.existsSync(fullPath)) {
              fileContent = fs.readFileSync(fullPath, "utf-8");
            }
          }
          if (!fileContent) fileContent = vuln.codeSnippet || "";

          const ext = path.extname(vuln.filePath || "").slice(1) || "txt";
          const langMap: Record<string, string> = { ts: "typescript", tsx: "typescript", js: "javascript", jsx: "javascript", py: "python", java: "java", go: "go", rb: "ruby", php: "php", cs: "csharp" };
          const lang = langMap[ext] || ext;

          const fixPrompt = buildFixPrompt(
            { title: vuln.title, severity: vuln.severity, cweId: vuln.cweId, filePath: vuln.filePath, lineStart: vuln.lineStart, codeSnippet: vuln.codeSnippet, description: vuln.description },
            fileContent,
            lang,
            // Enrich with DB knowledge (root causes + remediation)
            vuln.cweId ? await getKnowledgeForFinding(vuln.cweId).then((k) => k ? {
              rootCauses: k.rootCauses,
              remediation: k.catalog?.remediation,
              references: k.catalog?.references as string[] | undefined,
              validationGate: k.validationGate,
            } : undefined) : undefined
          );

          const fixResult = await generateWithGemini(fixPrompt, { temperature: 0.2, maxOutputTokens: 2000, companyId });
          scanTokens.input += fixResult?.inputTokens ?? 0;
          scanTokens.output += fixResult?.outputTokens ?? 0;
          scanTokens.cost += fixResult?.cost ?? 0;
          const parsed = parseAiJson<{ fixedCode?: string; explanation?: string }>(fixResult?.text);
          const candidate = parsed?.fixedCode || fixResult?.text;
          if (candidate) {
            // Prompt-injection defense: a malicious repo can try to smuggle a
            // backdoor into the generated fix. Reject fixes that introduce
            // dangerous primitives absent from the original code.
            const screening = validateGeneratedFix(fileContent, candidate);
            if (!screening.ok) {
              scanProgressStore.log(
                analysisId,
                "warning",
                `Fix RECHAZADO por screening de seguridad ${i + 1}/${fixableVulns.length}: ${screening.reasons[0]}`,
              );
            } else {
              await prisma.vulnerability.update({
                where: { id: vuln.id },
                data: {
                  smartFix: candidate,
                  fixExplanation: parsed?.explanation || null,
                },
              });
              fixesGenerated++;
              scanProgressStore.log(analysisId, "success", `Fix generado ${i + 1}/${fixableVulns.length}: ${vuln.title.slice(0, 50)}`);
            }
          } else {
            scanProgressStore.log(analysisId, "warning", `Fix sin respuesta IA ${i + 1}/${fixableVulns.length}: ${vuln.title.slice(0, 40)}`);
          }
        } catch (fixErr) {
          console.error(`Fix generation failed for vuln ${vuln.id}:`, fixErr);
          scanProgressStore.log(analysisId, "warning", `Fix falló ${i + 1}/${fixableVulns.length}: ${vuln.title.slice(0, 40)}`);
        }
      }
      scanProgressStore.log(analysisId, fixesGenerated > 0 ? "success" : "warning", `Fixes IA generados para ${fixesGenerated}/${fixableVulns.length} vulnerabilidades`);
    }

    // === DELTA COMPARISON (New/Existing/Fixed/Reopened) ===
    scanProgressStore.log(analysisId, "info", "Fase: Comparación delta con escaneo anterior...");
    try {
      // Generate fingerprints for AI-detected vulns too
      const aiVulns = await prisma.vulnerability.findMany({
        where: { analysisId, fingerprint: null },
        select: { id: true, cweId: true, filePath: true, codeSnippet: true },
      });
      for (const v of aiVulns) {
        const fp = generateFingerprint(v.filePath || "", v.cweId || "", v.codeSnippet || "");
        await prisma.vulnerability.update({ where: { id: v.id }, data: { fingerprint: fp, detectionMethod: "AI" } });
        deterministicFindings.push({ fingerprint: fp, cweId: v.cweId || "", filePath: v.filePath || "" });
      }

      const deltaMap = await computeDelta(analysis.appVersion.applicationId, analysisId, deterministicFindings);
      // Apply delta status to current vulns
      const currentVulns = await prisma.vulnerability.findMany({
        where: { analysisId },
        select: { id: true, fingerprint: true },
      });
      for (const v of currentVulns) {
        if (v.fingerprint && deltaMap.has(v.fingerprint)) {
          await prisma.vulnerability.update({
            where: { id: v.id },
            data: { deltaStatus: deltaMap.get(v.fingerprint)!.deltaStatus },
          });
        }
      }
      const newCount = [...deltaMap.values()].filter((d) => d.deltaStatus === "NEW").length;
      const existingCount = [...deltaMap.values()].filter((d) => d.deltaStatus === "EXISTING").length;
      scanProgressStore.log(analysisId, "success", `Delta: ${newCount} nuevos, ${existingCount} existentes`);
    } catch (deltaErr) {
      console.error("Delta computation failed (non-fatal):", deltaErr);
      scanProgressStore.log(analysisId, "warning", "Delta: error no crítico durante comparación");
    }

    // === COMPLETION ===
    scanProgressStore.updateStep(analysisId, "report", { status: "running", progress: 50 });
    scanProgressStore.log(analysisId, "info", "Generando reporte final...");

    const duration = Math.round((Date.now() - startTime) / 1000);

    const vulnCounts = await prisma.vulnerability.groupBy({
      by: ["severity"],
      where: { analysisId },
      _count: true,
    });

    const counts: Record<string, number> = {};
    for (const vc of vulnCounts) {
      counts[vc.severity] = vc._count;
    }
    // Ground truth is the DB (post-dedup), not the in-memory accumulator.
    const finalTotal = Object.values(counts).reduce((a, b) => a + b, 0);

    await prisma.analysis.update({
      where: { id: analysisId },
      data: {
        status: "COMPLETED",
        completedAt: new Date(),
        duration,
        totalIssues: finalTotal,
        criticalCount: counts["CRITICAL"] || 0,
        highCount: counts["HIGH"] || 0,
        mediumCount: counts["MEDIUM"] || 0,
        lowCount: counts["LOW"] || 0,
        infoCount: counts["INFO"] || 0,
        falsePositives: fpCount,
        inputTokens: BigInt(scanTokens.input),
        outputTokens: BigInt(scanTokens.output),
        estimatedCost: scanTokens.cost,
      },
    });

    await prisma.application.update({
      where: { id: analysis.appVersion.applicationId },
      data: { lastScanAt: new Date() },
    });

    scanProgressStore.log(analysisId, "success", `Análisis completado en ${duration}s — ${finalTotal} hallazgos, ${fpCount} FP eliminados`);
    scanProgressStore.log(analysisId, "info", `Tokens: ${scanTokens.input.toLocaleString()} in / ${scanTokens.output.toLocaleString()} out — Costo estimado: $${scanTokens.cost.toFixed(4)}`);
    scanProgressStore.updateStep(analysisId, "report", { status: "completed", progress: 100 });
    scanProgressStore.complete(analysisId);

    // Notify messaging channels of completion (fire-and-forget)
    if (companyId) {
      notifyScanCompleted(companyId, {
        analysisId,
        appName: analysis.appVersion.application.name,
        version: analysis.appVersion.version,
        scanTypes,
        totalVulns,
        critical: counts["CRITICAL"] || 0,
        high: counts["HIGH"] || 0,
        medium: counts["MEDIUM"] || 0,
        low: counts["LOW"] || 0,
        info: counts["INFO"] || 0,
        duration,
      }).catch(() => {});
    }
  } catch (error) {
    console.error("Analysis failed:", error);
    const duration = Math.round((Date.now() - startTime) / 1000);
    const errMsg = error instanceof Error ? error.message : "Unknown error";
    await prisma.analysis.update({
      where: { id: analysisId },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        duration,
        errorMessage: errMsg,
      },
    });
    scanProgressStore.log(analysisId, "error", `Error fatal: ${errMsg}`);
    scanProgressStore.fail(analysisId, errMsg);

    // Notify messaging channels of failure (fire-and-forget)
    if (failCompanyId) {
      notifyScanFailed(failCompanyId, {
        appName: failAppName,
        version: failVersion,
        error: errMsg,
      }).catch(() => {});
    }
  }
}

export async function gatherSourceCode(
  versionId: string,
  sourceUrl: string | null
): Promise<SourceCodeBundle> {
  const result: SourceCodeBundle = { code: "", depFiles: [] };

  // Check for uploaded files in the uploads directory
  const fs = await import("fs/promises");
  const path = await import("path");
  const uploadDir = path.join(process.cwd(), "uploads", versionId);

  try {
    const stat = await fs.stat(uploadDir);
    if (stat.isDirectory()) {
      const files = await walkDir(uploadDir);
      const codeExtensions = [".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs"];
      const depFiles = ["package.json", "requirements.txt", "pom.xml", "Cargo.toml", "go.mod", "Gemfile"];

      const codeChunks: string[] = [];
      for (const file of files) {
        const ext = path.extname(file).toLowerCase();
        const basename = path.basename(file);
        const content = await fs.readFile(file, "utf-8");

        if (depFiles.includes(basename)) {
          result.depFiles.push({ filename: basename, content });
        }

        if (codeExtensions.includes(ext)) {
          codeChunks.push(`// === ${path.relative(uploadDir, file)} ===\n${content}`);
        }
      }

      result.code = codeChunks.join("\n\n");
    }
  } catch {
    // Upload dir doesn't exist — check if URL source
  }

  // If no uploaded files but we have a GitHub/URL source, try to fetch
  if (!result.code && sourceUrl) {
    try {
      const res = await fetch(sourceUrl);
      if (res.ok) {
        const text = await res.text();
        result.code = text;
      }
    } catch {
      console.error("Failed to fetch source from URL:", sourceUrl);
    }
  }

  // Provide a fallback sample for demo/testing when no source is available
  if (!result.code) {
    result.code = `// No source code available for analysis.
// Upload source code or connect a GitHub repository to enable full scanning.`;
  }

  return result;
}

async function walkDir(dir: string): Promise<string[]> {
  const fs = await import("fs/promises");
  const path = await import("path");
  const files: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (EXCLUDED_DIRS.has(entry.name)) continue;
    if (entry.isDirectory()) {
      const subFiles = await walkDir(fullPath);
      files.push(...subFiles);
    } else {
      files.push(fullPath);
    }
  }

  return files;
}

async function analyzeFileStats(versionId: string): Promise<{ totalFiles: number; languages: string[]; linesOfCode: number }> {
  const fs = await import("fs/promises");
  const path = await import("path");
  const uploadDir = path.join(process.cwd(), "uploads", versionId);

  const extToLang: Record<string, string> = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript",
    ".py": "Python", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".c": "C", ".cpp": "C++", ".rs": "Rust", ".swift": "Swift",
    ".kt": "Kotlin", ".scala": "Scala", ".abap": "ABAP", ".sql": "SQL",
    ".html": "HTML", ".css": "CSS", ".vue": "Vue", ".svelte": "Svelte",
  };

  try {
    const files = await walkDir(uploadDir);
    const langSet = new Set<string>();
    let linesOfCode = 0;
    const codeExts = new Set(Object.keys(extToLang));

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      if (codeExts.has(ext)) {
        langSet.add(extToLang[ext]);
        try {
          const content = await fs.readFile(file, "utf-8");
          linesOfCode += content.split("\n").length;
        } catch { /* skip unreadable */ }
      }
    }

    return { totalFiles: files.length, languages: [...langSet], linesOfCode };
  } catch {
    return { totalFiles: 0, languages: [], linesOfCode: 0 };
  }
}

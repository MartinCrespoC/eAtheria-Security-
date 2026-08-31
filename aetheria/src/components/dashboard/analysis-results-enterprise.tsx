"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft, Clock, Shield, FileCode, ChevronDown, ChevronUp,
  ExternalLink, Wrench, Bug, Copy, Check, Download, Filter,
  Package, AlertTriangle, X, Search, Layers, Sparkles, FileArchive,
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────

interface VulnData {
  id: string;
  severity: string;
  confidence: string;
  category: string;
  title: string;
  description: string;
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  codeSnippet: string | null;
  cweId: string | null;
  cveId: string | null;
  owaspTop10: string | null;
  aiValidated: boolean;
  isFalsePositive: boolean;
  fpReason: string | null;
  smartFix: string | null;
  fixExplanation: string | null;
  status: string;
  detectionMethod: string | null;
  deltaStatus: string | null;
  rootCause: string | null;
  packageName: string | null;
  packageVersion: string | null;
  ecosystem: string | null;
}

interface KnowledgeEntry {
  compliance: { pciDss?: string; hipaa?: string; nist80053?: string; iso27001?: string; owasp2021?: string; owasp2017?: string; mitreTop25?: number } | null;
  catalog: { name?: string; remediation?: string; references?: string[]; rank?: number; year?: number } | null;
  skills: { slug: string; name: string; reportCount: number }[];
  rootCauses: { title: string; detail: string }[];
  impactExamples: { scenario: string; description: string; cveIds: string[] }[];
  validationGate: { question: string; criteria: string }[];
  chains: { targetSkill: string; primitive: string }[];
}

interface AnalysisData {
  id: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  duration: number | null;
  errorMessage: string | null;
  scanTypes: unknown;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  falsePositives: number;
  createdAt: string;
  sbomGenerated: boolean;
  appVersion: {
    id: string;
    version: string;
    application: { id: string; name: string; slug: string; language?: string | null };
  };
  vulnerabilities: VulnData[];
}

interface Props {
  analysis: AnalysisData;
  knowledgeMap: Record<string, KnowledgeEntry>;
  showInfoFindings?: boolean;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  INFO: "bg-slate-500/20 text-text-secondary border-slate-500/30",
};

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const DETECTION_METHODS = ["TAINT", "SECRET", "IAC", "AI", "SCA", "DAST", "RULE"];

// ─── Component ───────────────────────────────────────────────────────────────

export function AnalysisResultsEnterprise({ analysis, knowledgeMap, showInfoFindings = true }: Props) {
  const [activeTab, setActiveTab] = useState<"hallazgos" | "cumplimiento" | "dependencias">("hallazgos");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedFix, setCopiedFix] = useState<string | null>(null);

  // Filters
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [depsOnly, setDepsOnly] = useState(false);
  const [cweSearch, setCweSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [hideFP, setHideFP] = useState(true);
  const [deltaFilter, setDeltaFilter] = useState("");
  const [textSearch, setTextSearch] = useState("");

  const scanTypes = Array.isArray(analysis.scanTypes) ? (analysis.scanTypes as string[]) : [];
  const vulns = analysis.vulnerabilities;

  // Compute risk score (weighted)
  const riskScore = useMemo(() => {
    const weights: Record<string, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 };
    const total = vulns.reduce((sum, v) => sum + (weights[v.severity] || 0), 0);
    const maxPossible = vulns.length * 10;
    return maxPossible > 0 ? Math.min(100, Math.round((total / maxPossible) * 100)) : 0;
  }, [vulns]);

  // Filtered vulns
  const filtered = useMemo(() => {
    return vulns.filter((v) => {
      if (!showInfoFindings && v.severity === "INFO") return false;
      if (hideFP && v.isFalsePositive) return false;
      if (sevFilter.size > 0 && !sevFilter.has(v.severity)) return false;
      if (categoryFilter && v.category !== categoryFilter) return false;
      if (methodFilter && v.detectionMethod !== methodFilter) return false;
      if (depsOnly && v.detectionMethod !== "SCA" && v.category !== "Dependency") return false;
      if (cweSearch && !(v.cweId || "").toLowerCase().includes(cweSearch.toLowerCase())) return false;
      if (statusFilter && v.status !== statusFilter) return false;
      if (deltaFilter && v.deltaStatus !== deltaFilter) return false;
      if (textSearch) {
        const q = textSearch.toLowerCase();
        if (!v.title.toLowerCase().includes(q) && !(v.filePath || "").toLowerCase().includes(q) && !v.description.toLowerCase().includes(q)) return false;
      }
      return true;
    }).sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
  }, [vulns, sevFilter, categoryFilter, methodFilter, depsOnly, cweSearch, statusFilter, hideFP, deltaFilter, textSearch, showInfoFindings]);

  // Unique categories
  const categories = useMemo(() => [...new Set(vulns.map((v) => v.category))].sort(), [vulns]);

  // Dependency vulns
  const depVulns = useMemo(() => vulns.filter((v) => v.detectionMethod === "SCA" || v.category === "Dependency"), [vulns]);

  // Compliance data
  const complianceData = useMemo(() => {
    const standards: Record<string, { requirement: string; count: number }[]> = {};
    for (const v of vulns) {
      if (!v.cweId || v.isFalsePositive) continue;
      const k = knowledgeMap[v.cweId];
      if (!k?.compliance) continue;
      const c = k.compliance;
      if (c.owasp2021) pushStandard(standards, "OWASP Top 10 2021", c.owasp2021);
      if (c.pciDss) pushStandard(standards, "PCI-DSS", c.pciDss);
      if (c.nist80053) pushStandard(standards, "NIST 800-53", c.nist80053);
      if (c.iso27001) pushStandard(standards, "ISO 27001", c.iso27001);
      if (c.hipaa) pushStandard(standards, "HIPAA", c.hipaa);
    }
    return standards;
  }, [vulns, knowledgeMap]);

  const hasFilters = sevFilter.size > 0 || categoryFilter || methodFilter || depsOnly || cweSearch || statusFilter || deltaFilter || textSearch;
  const fpCount = vulns.filter((v) => v.isFalsePositive).length;
  const aiValidatedCount = vulns.filter((v) => v.aiValidated).length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Link href={`/dashboard/applications/${analysis.appVersion.application.id}`}>
            <Button variant="ghost" size="sm"><ArrowLeft className="h-4 w-4" /></Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-text-primary">{analysis.appVersion.application.name}</h1>
              <Badge variant={analysis.status === "COMPLETED" ? "success" : analysis.status === "FAILED" ? "destructive" : "info"}>{analysis.status}</Badge>
            </div>
            <p className="text-text-secondary text-sm mt-0.5">
              v{analysis.appVersion.version} · {scanTypes.join(", ")} · {new Date(analysis.createdAt).toLocaleDateString("es-ES")}
              {analysis.duration != null && <span className="ml-2"><Clock className="h-3 w-3 inline" /> {analysis.duration}s</span>}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <PromptZipButton analysis={analysis} />
          <AIFixPromptButton analysis={analysis} knowledgeMap={knowledgeMap} />
          <ExportMenu analysisId={analysis.id} />
        </div>
      </div>

      {/* Executive Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <SummaryCard label="Risk Score" value={`${riskScore}`} sub={riskScore >= 70 ? "Crítico" : riskScore >= 40 ? "Moderado" : "Bajo"} color={riskScore >= 70 ? "text-red-400" : riskScore >= 40 ? "text-amber-400" : "text-emerald-400"} />
        <SummaryCard label="Hallazgos" value={`${vulns.length}`} sub={`${fpCount} FP excluidos`} color="text-text-primary" />
        <SummaryCard label="Cumplimiento" value={`${Object.keys(complianceData).length}`} sub="estándares cubiertos" color="text-accent" />
        <SummaryCard label="Dependencias" value={`${depVulns.length}`} sub="en riesgo" color="text-orange-400" />
        <SummaryCard label="Validados IA" value={`${aiValidatedCount}`} sub="hallazgos confirmados" color="text-emerald-400" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(["hallazgos", "cumplimiento", "dependencias"] as const).map((tab) => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${activeTab === tab ? "border-cyan-500 text-accent" : "border-transparent text-text-secondary hover:text-text-primary"}`}>
            {tab === "hallazgos" ? `Hallazgos (${filtered.length})` : tab === "cumplimiento" ? "Cumplimiento" : `Dependencias (${depVulns.length})`}
          </button>
        ))}
      </div>

      {/* HALLAZGOS TAB */}
      {activeTab === "hallazgos" && (
        <>
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg border border-border bg-card">
            {/* Severity chips */}
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => {
              const count = vulns.filter((v) => v.severity === sev && !(hideFP && v.isFalsePositive)).length;
              const active = sevFilter.has(sev);
              return (
                <button key={sev} onClick={() => { const n = new Set(sevFilter); n.has(sev) ? n.delete(sev) : n.add(sev); setSevFilter(n); }}
                  className={`px-2 py-1 rounded text-[10px] font-bold border transition-all ${active ? SEV_COLORS[sev] : "border-border text-text-muted hover:border-slate-500"}`}>
                  {sev} ({count})
                </button>
              );
            })}
            <div className="w-px h-5 bg-surface-hover mx-1" />
            {/* Dependencias toggle */}
            <button onClick={() => setDepsOnly(!depsOnly)}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium border transition-all ${depsOnly ? "border-orange-500/50 bg-orange-500/10 text-orange-400" : "border-border text-text-muted hover:border-slate-500"}`}>
              <Package className="h-3 w-3" /> Dependencias
            </button>
            {/* Hide FP toggle */}
            <button onClick={() => setHideFP(!hideFP)}
              className={`px-2 py-1 rounded text-[10px] font-medium border transition-all ${hideFP ? "border-cyan-500/50 bg-cyan-500/10 text-accent" : "border-border text-text-muted"}`}>
              Ocultar FP
            </button>
            <div className="w-px h-5 bg-surface-hover mx-1" />
            {/* Dropdowns */}
            <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-text-primary">
              <option value="">Categoría</option>
              {categories.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <select value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)} className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-text-primary">
              <option value="">Método</option>
              {DETECTION_METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
            <select value={deltaFilter} onChange={(e) => setDeltaFilter(e.target.value)} className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-text-primary">
              <option value="">Delta</option>
              <option value="NEW">NEW</option>
              <option value="EXISTING">EXISTING</option>
              <option value="REOPENED">REOPENED</option>
            </select>
            {/* CWE search */}
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-text-muted" />
              <input value={cweSearch} onChange={(e) => setCweSearch(e.target.value)} placeholder="CWE-..." className="bg-surface border border-border rounded pl-6 pr-2 py-1 text-[11px] text-text-primary w-24" />
            </div>
            {/* Text search */}
            <div className="relative flex-1 min-w-[120px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-text-muted" />
              <input value={textSearch} onChange={(e) => setTextSearch(e.target.value)} placeholder="Buscar..." className="w-full bg-surface border border-border rounded pl-6 pr-2 py-1 text-[11px] text-text-primary" />
            </div>
            {hasFilters && (
              <button onClick={() => { setSevFilter(new Set()); setCategoryFilter(""); setMethodFilter(""); setDepsOnly(false); setCweSearch(""); setStatusFilter(""); setDeltaFilter(""); setTextSearch(""); }}
                className="flex items-center gap-1 px-2 py-1 rounded text-[10px] text-red-400 hover:bg-red-500/10 border border-red-500/30">
                <X className="h-3 w-3" /> Limpiar
              </button>
            )}
          </div>

          {/* Findings List */}
          <div className="space-y-1.5">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-text-muted">
                <Shield className="h-8 w-8 mb-2 opacity-40" />
                <p>{vulns.length === 0 ? "Sin vulnerabilidades detectadas" : "Sin resultados para estos filtros"}</p>
              </div>
            ) : (
              filtered.map((v) => (
                <FindingRow key={v.id} v={v} expanded={expandedId === v.id}
                  onToggle={() => setExpandedId(expandedId === v.id ? null : v.id)}
                  knowledge={v.cweId ? knowledgeMap[v.cweId] : undefined}
                  copiedFix={copiedFix} setCopiedFix={setCopiedFix} />
              ))
            )}
          </div>
        </>
      )}

      {/* CUMPLIMIENTO TAB */}
      {activeTab === "cumplimiento" && (
        <div className="space-y-4">
          {Object.keys(complianceData).length === 0 ? (
            <p className="text-text-muted text-sm py-8 text-center">No hay mappings de cumplimiento para los hallazgos actuales.</p>
          ) : (
            Object.entries(complianceData).map(([standard, reqs]) => (
              <div key={standard} className="rounded-lg border border-border bg-card p-4">
                <h3 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-2"><Layers className="h-4 w-4 text-accent" /> {standard}</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {reqs.sort((a, b) => b.count - a.count).map((r) => (
                    <div key={r.requirement} className="flex items-center justify-between px-3 py-2 rounded bg-surface border border-border">
                      <span className="text-xs text-text-primary">{r.requirement}</span>
                      <Badge variant={r.count > 3 ? "destructive" : r.count > 1 ? "warning" : "default"} className="text-[10px]">{r.count}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* DEPENDENCIAS TAB */}
      {activeTab === "dependencias" && (
        <div className="space-y-3">
          {depVulns.length === 0 ? (
            <p className="text-text-muted text-sm py-8 text-center">No se encontraron vulnerabilidades en dependencias.</p>
          ) : (
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-surface">
                  <tr className="text-left text-text-secondary">
                    <th className="px-3 py-2 font-medium">Paquete</th>
                    <th className="px-3 py-2 font-medium">Versión</th>
                    <th className="px-3 py-2 font-medium">Ecosistema</th>
                    <th className="px-3 py-2 font-medium">CVE</th>
                    <th className="px-3 py-2 font-medium">Severidad</th>
                    <th className="px-3 py-2 font-medium">Fix</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {depVulns.map((v) => (
                    <tr key={v.id} className="hover:bg-surface">
                      <td className="px-3 py-2 text-text-primary font-mono">{v.packageName || v.title}</td>
                      <td className="px-3 py-2 text-text-secondary font-mono">{v.packageVersion || "-"}</td>
                      <td className="px-3 py-2"><Badge variant="outline" className="text-[9px]">{v.ecosystem || "npm"}</Badge></td>
                      <td className="px-3 py-2">
                        {v.cveId ? (
                          <a href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">{v.cveId}</a>
                        ) : "-"}
                      </td>
                      <td className="px-3 py-2"><span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${SEV_COLORS[v.severity]}`}>{v.severity}</span></td>
                      <td className="px-3 py-2 text-emerald-400">{v.smartFix?.match(/to ([\d.]+)/)?.[1] || v.smartFix?.slice(0, 40) || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {analysis.sbomGenerated && (
            <Button variant="outline" size="sm" onClick={() => window.open(`/api/analyses/${analysis.id}/export?format=json`, "_blank")}>
              <Download className="h-3.5 w-3.5 mr-1.5" /> Descargar SBOM (CycloneDX)
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function SummaryCard({ label, value, sub, color }: { label: string; value: string; sub: string; color: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-3 text-center">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-[11px] text-text-secondary font-medium">{label}</p>
      <p className="text-[10px] text-text-muted">{sub}</p>
    </div>
  );
}

function ExportMenu({ analysisId }: { analysisId: string }) {
  const [open, setOpen] = useState(false);
  const formats = [
    { label: "PDF", fmt: "pdf" },
    { label: "Excel", fmt: "xlsx" },
    { label: "CSV", fmt: "csv" },
    { label: "JSON", fmt: "json" },
    { label: "SARIF", fmt: "sarif" },
  ];
  return (
    <div className="relative">
      <Button variant="outline" size="sm" onClick={() => setOpen(!open)} className="gap-1.5">
        <Download className="h-3.5 w-3.5" /> Exportar
      </Button>
      {open && (
        <div className="absolute right-0 mt-1 w-32 rounded-lg border border-border bg-surface shadow-xl z-50">
          {formats.map((f) => (
            <button key={f.fmt} onClick={() => { window.open(`/api/analyses/${analysisId}/export?format=${f.fmt}`, "_blank"); setOpen(false); }}
              className="w-full px-3 py-2 text-xs text-text-primary hover:bg-surface-hover text-left first:rounded-t-lg last:rounded-b-lg">
              {f.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function PromptZipButton({ analysis }: { analysis: AnalysisData }) {
  const [copied, setCopied] = useState(false);

  const generatePrompt = () => {
    const appName = analysis.appVersion.application.name;
    const version = analysis.appVersion.version;

    // Files EATHERIA flagged as containing secrets — must be excluded/sanitized
    const secretFiles = Array.from(
      new Set(
        analysis.vulnerabilities
          .filter((v) => !v.isFalsePositive && (v.detectionMethod === "SECRET" || /secret|credential|hardcoded|high-entropy/i.test(`${v.category} ${v.title}`)))
          .map((v) => v.filePath)
          .filter((f): f is string => Boolean(f))
      )
    );

    const prompt = `# EATHERIA Security — Prompt de Empaquetado Seguro (Safe Zip + .gitignore)
# Aplicación: ${appName} v${version}
# Generado: ${new Date().toLocaleString("es-ES")}

## OBJETIVO

Eres un ingeniero de seguridad. Prepara este proyecto para publicarlo en git y/o compartirlo de forma SEGURA:
1. Configura \`.gitignore\` para que NADA privado se publique en git.
2. Genera un **ZIP limpio** con SOLO el código core del proyecto: sin secretos, sin docker con credenciales, sin documentación extra, sin dependencias ni artefactos de build.

---

## PARTE 1 — .gitignore (excluir todo lo privado)

Revisa el \`.gitignore\` existente y COMPLETA con estos patrones (agrega solo los que falten, no dupliques):

\`\`\`gitignore
# === Secretos y credenciales ===
.env
.env.*
!.env.example
*.key
*.pem
*.p12
*.pfx
*.jks
*.keystore
*.ppk
secrets/
credentials/
*.secret
# Carpetas SSH / claves privadas (NUNCA publicar)
ssh/
**/ssh/
id_rsa
id_rsa.pub
id_ed25519
id_ed25519.pub

# === Docker con credenciales inline ===
# Si docker-compose*.yml tiene contraseñas/connection strings, mueve los valores
# a .env y referéncialos con \${VAR}. Si no puedes sanearlos, exclúyelos:
docker-compose.prod.yml
docker-compose.production.yml
compose.prod.yml
.docker/

# === Dependencias y builds ===
node_modules/
dist/
build/
out/
.next/
.nuxt/
.svelte-kit/
.turbo/
.cache/
.parcel-cache/
coverage/
*.tsbuildinfo
# Según lenguaje (Python / JVM / etc.)
__pycache__/
*.pyc
.venv/
venv/
target/

# === Bases de datos, logs y dumps ===
*.sqlite
*.db
*.log
logs/
dumps/

# === Carpetas ocultas que empiezan con "." (git, editores IA, tooling) ===
# Git / CI
.git/
.github/
.gitlab/
# Tooling de repo
.husky/
.idea/
.vscode/
# Editores y asistentes de IA
.cursor/
.cursorrules
.windsurf/
.windsurfrules
.devin/
.qoder/
.claude/
.copilot/
.aider*
.continue/
.codeium/
.tabnine/
.ia/
.ai/
# Runtime / mensajería (según stack, p.ej. WhatsApp)
.wwebjs_auth/
.wwebjs_cache/

# Opción agresiva: ignora TODA carpeta que empiece con "." de una vez.
# Descomenta si prefieres barrer todo (revisa luego con git qué se excluyó):
# .*/

# === Despliegues / infraestructura ===
deploy/
deploys/
.deploy/
deployment/
infra/
terraform/
.terraform/
*.tfstate
*.tfstate.*

# === Sistemas operativos ===
.DS_Store
Thumbs.db
desktop.ini

# === Documentación extra (opcional) ===
# Descomenta si NO quieres publicar docs internos:
# docs/
\`\`\`

---

## PARTE 2 — ZIP limpio del core del proyecto

Genera un ZIP que contenga SOLO lo necesario para reconstruir y analizar el proyecto.

**INCLUIR:** código fuente (src/, apps/, lib/), \`package.json\`, lockfiles, \`.env.example\`, \`README.md\`, configs de build saneadas.
**EXCLUIR:** todo lo listado en el .gitignore + \`.git/\` + documentación interna.

### Archivos que EATHERIA detectó con secretos — EXCLUIR o SANEAR obligatoriamente:
${secretFiles.length > 0 ? secretFiles.map((f) => `- \`${f}\``).join("\n") : "- (ninguno detectado en el último escaneo; aplica igualmente las reglas generales)"}

Para cada uno: si es \`.env\` o clave privada → EXCLUIR del ZIP. Si es \`docker-compose.yml\` → sanear (mover secretos a \`.env\` con \${VAR}) o excluir la variante de producción.

### Comando sugerido (ajusta a tu estructura):
\`\`\`bash
zip -r proyecto-clean.zip . \\
  -x "*.git*" \\
  -x "*node_modules*" \\
  -x "*.env" -x "*.env.*" -x "!*.env.example" \\
  -x "*.key" -x "*.pem" -x "*.p12" -x "*.pfx" -x "*.ppk" \\
  -x "*dist*" -x "*build*" -x "*.next*" -x "*.nuxt*" -x "*out*" \\
  -x "*coverage*" -x "*.turbo*" -x "*.cache*" \\
  -x "*.sqlite" -x "*.db" -x "*.log" \\
  -x "*docs*" \\
  -x "*docker-compose.prod.yml" -x "*docker-compose.production.yml" \\
  -x "*/.cursor/*" -x "*/.windsurf/*" -x "*/.qoder/*" -x "*/.devin/*" \\
  -x "*/.idea/*" -x "*/.vscode/*" -x "*/.husky/*" -x "*/.github/*" \\
  -x "*/ssh/*" -x "*id_rsa*" -x "*id_ed25519*" \\
  -x "*deploy/*" -x "*deploys/*" -x "*.terraform*" -x "*.tfstate*"
\`\`\`

### Verificación OBLIGATORIA antes de compartir:
\`\`\`bash
unzip -l proyecto-clean.zip | grep -iE "\\.env|\\.key|\\.pem|\\.ppk|secret|password|credential|docker-compose.prod|/ssh/|id_rsa|id_ed25519|\\.cursor|\\.windsurf|\\.qoder|\\.devin|deploy|\\.tfstate"
\`\`\`
Si ese comando devuelve resultados, el ZIP AÚN contiene privados → exclúyelos y repite hasta que no devuelva nada.

---

## REGLAS
- NUNCA incluyas secretos reales en el ZIP ni en git.
- \`.env.example\` SÍ se incluye (con placeholders vacíos) para documentar las variables necesarias.
- Si un docker-compose tiene credenciales inline, sanéalas antes de incluirlo, o exclúyelo.
- Ante la duda, EXCLUYE.
- Al final, reporta: qué se agregó al .gitignore, qué archivos se excluyeron del ZIP y el resultado de la verificación.
`;

    return prompt;
  };

  const handleClick = () => {
    const prompt = generatePrompt();
    if (prompt.length > 40000) {
      const blob = new Blob([prompt], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aetheria-safe-zip-prompt-${analysis.appVersion.application.name.replace(/\s+/g, "-").toLowerCase()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      navigator.clipboard.writeText(prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  return (
    <Button variant="outline" size="sm" onClick={handleClick} className="gap-1.5 border-amber-500/40 text-amber-400 hover:bg-amber-500/10 hover:text-amber-300">
      {copied ? <Check className="h-3.5 w-3.5" /> : <FileArchive className="h-3.5 w-3.5" />}
      {copied ? "Copiado!" : "Prompt Zip"}
    </Button>
  );
}

function AIFixPromptButton({ analysis, knowledgeMap }: { analysis: AnalysisData; knowledgeMap: Record<string, KnowledgeEntry> }) {
  const [copied, setCopied] = useState(false);

  const generatePrompt = () => {
    const actionableVulns = analysis.vulnerabilities.filter(
      (v) => !v.isFalsePositive && ["CRITICAL", "HIGH", "MEDIUM"].includes(v.severity)
    );

    // Dependencias con advisories (SCA) — se listan en su propia sección, incluso si son INFO
    const depFindings = analysis.vulnerabilities.filter(
      (v) => !v.isFalsePositive && (v.category === "Dependency" || v.detectionMethod === "SCA")
    );

    const appName = analysis.appVersion.application.name;
    const version = analysis.appVersion.version;
    const appLanguage = analysis.appVersion.application.language?.trim() || "detectar automáticamente según el repositorio";

    let prompt = `# EATHERIA Security — Prompt de Corrección Automática
# Aplicación: ${appName} v${version}
# Lenguaje / Stack: ${appLanguage}
# Generado: ${new Date().toLocaleString("es-ES")}
# Hallazgos a corregir: ${actionableVulns.length} (CRITICAL/HIGH/MEDIUM) + ${depFindings.length} dependencias (SCA)

## INSTRUCCIONES PARA EL ASISTENTE DE IA

Eres un ingeniero de seguridad senior. Tu tarea tiene TRES partes:
**PARTE A** — Corregir TODAS las vulnerabilidades listadas en la sección "VULNERABILIDADES A CORREGIR".
**PARTE B** — Realizar una auditoría proactiva de TODO el proyecto (sección "AUDITORÍA DE SEGURIDAD PROACTIVA") y corregir también lo que encuentres.
**PARTE C** — Blindar el proyecto para el futuro (sección "SISTEMA DE REGLAS Y SKILLS DE SEGURIDAD"): configura reglas automatizadas y skills de IA para que los cambios futuros no reintroduzcan vulnerabilidades.

Para cada vulnerabilidad de la Parte A:
1. Localiza el archivo y línea indicados
2. Aplica el fix sugerido (si existe) o implementa la mejor práctica de seguridad para el CWE indicado
3. Asegúrate de no romper funcionalidad existente
4. Si es una dependencia vulnerable, actualiza a la versión segura mínima
5. Después de TODOS los fixes, el código debe pasar un re-escaneo de seguridad sin hallazgos CRITICAL/HIGH/MEDIUM

## REGLAS
- Este prompt es AGNÓSTICO de lenguaje: aplica a cualquier stack soportado (JS/TS, Python, Java, Kotlin, Scala, C#, PHP, Ruby, Go, Rust, Swift, C/C++, ABAP). Detecta el lenguaje/framework real del proyecto y usa sus convenciones y herramientas idiomáticas en cada fix.
- NO elimines funcionalidad, solo corrige la vulnerabilidad
- Prefiere soluciones mínimas y quirúrgicas
- Si un fix requiere cambiar una dependencia, indica el comando exacto (npm install, pip install, etc.)
- Para secretos hardcodeados: mueve a variables de entorno (.env) y agrega al .gitignore
- Para XSS: usa sanitización o escaping apropiado al contexto
- Para SQL Injection: usa queries parametrizadas
- Para path traversal: valida y normaliza rutas

---

## VULNERABILIDADES A CORREGIR

`;

    for (let i = 0; i < actionableVulns.length; i++) {
      const v = actionableVulns[i];
      const knowledge = v.cweId ? knowledgeMap[v.cweId] : undefined;

      prompt += `### ${i + 1}. [${v.severity}] ${v.title}
`;
      prompt += `- **CWE:** ${v.cweId || "N/A"}`;
      if (v.cveId) prompt += ` | **CVE:** ${v.cveId}`;
      prompt += "\n";
      prompt += `- **Archivo:** ${v.filePath || "desconocido"}${v.lineStart ? `:${v.lineStart}` : ""}\n`;
      prompt += `- **Categoría:** ${v.category}\n`;
      prompt += `- **Descripción:** ${v.description}\n`;

      if (v.codeSnippet) {
        prompt += `- **Código vulnerable:**\n\`\`\`\n${v.codeSnippet}\n\`\`\`\n`;
      }

      if (v.smartFix) {
        prompt += `- **Fix sugerido:**\n\`\`\`\n${v.smartFix}\n\`\`\`\n`;
        if (v.fixExplanation) prompt += `- **Explicación:** ${v.fixExplanation}\n`;
      }

      if (knowledge?.catalog?.remediation) {
        prompt += `- **Remediación (best practice):** ${knowledge.catalog.remediation}\n`;
      }

      if (v.packageName && v.packageVersion) {
        prompt += `- **Dependencia:** ${v.packageName}@${v.packageVersion} (${v.ecosystem || "npm"})\n`;
      }

      prompt += "\n";
    }

    // ── Dependencias vulnerables (SCA): siempre explícitas, incluso si son INFO ──
    if (depFindings.length > 0) {
      prompt += `## DEPENDENCIAS VULNERABLES (SCA) — ACTUALIZAR OBLIGATORIAMENTE

Estas dependencias del proyecto tienen advisories conocidos. Actualízalas a la **versión segura mínima** (no necesariamente la última mayor si rompe compatibilidad) y verifica con \`npm audit\` (o equivalente) que los advisories desaparezcan.

`;
      depFindings.forEach((d, i) => {
        prompt += `${i + 1}. **${d.packageName || d.title}@${d.packageVersion || "?"}** (${d.ecosystem || "npm"})`;
        if (d.cveId) prompt += ` — ${d.cveId}`;
        prompt += `\n   - Advisory: ${d.title}\n`;
        if (d.packageName) {
          prompt += `   - Acción: actualizar \`${d.packageName}\` a la versión parcheada más reciente compatible. Comando sugerido: \`npm install ${d.packageName}@latest\` (o fija la versión mínima segura indicada por el advisory).\n`;
        }
      });
      prompt += `\n> Si un advisory NO aplica a tu uso real (p.ej. no usas la funcionalidad afectada), documéntalo como riesgo aceptado con justificación en lugar de ignorarlo.\n\n`;
    }

    prompt += `---

## AUDITORÍA DE SEGURIDAD PROACTIVA (TODO EL PROYECTO)

Además de corregir los hallazgos listados arriba, realiza una **auditoría integral de seguridad** sobre TODO el código del proyecto.
Recorre cada archivo y módulo buscando proactivamente las siguientes clases de vulnerabilidad. Si encuentras alguna
que NO esté en la lista anterior, **corrígela también** aplicando la mejor práctica correspondiente.

### 1. Secretos y Credenciales (CWE-798, CWE-321, CWE-259)
- Busca en TODO el repo: contraseñas, API keys, tokens JWT, connection strings, claves privadas, seeds de sesión.
- Patrones a buscar: \`password\`, \`secret\`, \`apiKey\`, \`api_key\`, \`token\`, \`Bearer \`, \`-----BEGIN\`, \`mongodb://\`, \`postgres://\`, \`mysql://\`, \`redis://\`, \`smtp://\`, \`AKIA\` (AWS), \`sk-\` (OpenAI).
- Todo secreto DEBE ir en variables de entorno (\`.env\`), nunca hardcodeado. Crea/actualiza \`.env.example\` con placeholders vacíos y agrega \`.env\` al \`.gitignore\`.

### 2. Inyección (CWE-89 SQLi, CWE-943 NoSQL, CWE-78 Command, CWE-79 XSS)
- SQL: toda query debe ser parametrizada (nada de concatenar strings). Revisa ORMs y queries raw.
- Comandos: nunca pasar input de usuario a \`exec\`/\`execSync\`/\`spawn\` sin sanitizar; evita shell=true.
- XSS: escapa/sanitiza todo lo que se renderice o se envíe en emails (subject y body). Usa librerías de sanitización (DOMPurify, xss).

### 3. SSRF y Open Redirect (CWE-918, CWE-601)
- SSRF: valida/allowlistea hosts externos (SMTP, webhooks, URLs provistas por usuario). No confíes en configuración dinámica sin filtro.
- Open Redirect: valida URLs de redirección contra una allowlist de dominios; rechaza \`//\` y esquemas externos.

### 4. Control de Acceso y Autenticación (CWE-284, CWE-639 IDOR, CWE-287, CWE-352 CSRF)
- Verifica que TODA ruta sensible exija autenticación y autorización (roles/permisos).
- IDOR: no confíes en IDs del cliente; verifica que el recurso pertenezca al usuario autenticado.
- CSRF: protege mutaciones con tokens CSRF o SameSite cookies.
- JWT: valida firma, expiración y emisor; no uses \`alg: none\`; secreto fuerte desde env.

### 5. Path Traversal y Archivos (CWE-22, CWE-434)
- Normaliza y valida rutas (\`path.resolve\` + verificar que quede dentro del directorio base). Rechaza \`..\`.
- Uploads: valida tipo MIME real (magic numbers), tamaño, y renombra archivos; nunca ejecutes subidos.

### 6. Criptografía y Datos Sensibles (CWE-327, CWE-312, CWE-319)
- No uses MD5/SHA1 para seguridad; usa bcrypt/argon2 para contraseñas, AES-256 para datos sensibles.
- Nunca almacenes sensibles en plaintext (PII, respuestas, tokens). Cifra en reposo si aplica.

### 7. Configuración y Exposición (CWE-16, CWE-200, CWE-209)
- Desactiva debug/stack traces en producción. No expongas versiones, internos ni \`.env\`.
- CORS: no uses \`*\` con credenciales. Headers de seguridad: CSP, X-Frame-Options, HSTS, X-Content-Type-Options.
- Rate limiting en login, registro y endpoints sensibles.

### 8. Dependencias (SCA)
- Revisa \`package.json\`/lockfiles (o equivalente) y actualiza dependencias con CVEs conocidos a la versión segura mínima.

### 9. Deserialización y XXE (CWE-502, CWE-611)
- No deserialices datos no confiables con \`eval\`/\`unserialize\`. En XML, desactiva entidades externas (DTD).

### Instrucciones para esta auditoría
- Prioriza CRITICAL y HIGH. Recorre backend, frontend, configs (docker-compose, .env, CI) y dependencias.
- Por cada problema nuevo que encuentres: indícalo brevemente (archivo:línea + CWE) y aplica el fix.
- Al final, entrega un resumen de los hallazgos adicionales corregidos.

---

## SISTEMA DE REGLAS Y SKILLS DE SEGURIDAD (PARTE C — cambios futuros)

Para que las vulnerabilidades NO se reintroduzcan en futuros cambios, configura el proyecto con controles automáticos y skills de IA.
Detecta el stack del proyecto (lenguaje, framework, IDE/CI presentes) y crea **solo los archivos que no existan**. No dupliques configuración existente.

### C1. Skills / reglas para asistentes de IA
Crea (si no existen) archivos de instrucciones de seguridad para que cualquier IA que edite el proyecto siga las buenas prácticas:
- \`.cursor/rules/security.mdc\` (Cursor) y/o \`.cursorrules\`
- \`.windsurfrules\` (Windsurf)
- \`.github/copilot-instructions.md\` (GitHub Copilot)
- \`AGENTS.md\` y/o \`CLAUDE.md\` (Claude / Codex / genérico)
- \`.qoder/rules/security.md\` (Qoder)

Contenido mínimo de cada skill (adaptado al stack):
- PROHIBIDO hardcodear secretos; siempre variables de entorno.
- Queries SIEMPRE parametrizadas; nunca concatenar input.
- Sanitizar/escapar toda salida (HTML, emails, logs).
- Validar y normalizar rutas y URLs (allowlist); rechazar \`..\` y redirecciones abiertas.
- AuthZ en toda ruta sensible; verificar propiedad del recurso (anti-IDOR).
- No pasar input a \`exec\`/shell; cifrar datos sensibles; bcrypt/argon2 para contraseñas.
- Antes de terminar cualquier tarea, revisar que no se introdujeron los patrones prohibidos de la Parte B.

### C2. Reglas de linting de seguridad (automatizadas)
Instala y configura el linter de seguridad idiomático del stack detectado (solo los que apliquen al proyecto):
- **JS/TS:** \`eslint-plugin-security\` + \`eslint-plugin-no-unsanitized\`.
- **Python:** \`bandit\` (config en \`pyproject.toml\`/\`.bandit\`).
- **Java:** \`spotbugs\` + \`find-sec-bugs\`. **Kotlin:** \`detekt\`. **Scala:** \`scalafix\` + reglas de seguridad.
- **C#:** \`SecurityCodeScan\` (analizador Roslyn). **PHP:** \`psalm\`/\`phpstan\` con reglas de seguridad.
- **Ruby:** \`brakeman\` + \`rubocop\`. **Go:** \`gosec\`. **Rust:** \`cargo-audit\` + \`clippy\`.
- **Swift:** \`swiftlint\`. **C/C++:** \`cppcheck\` + \`flawfinder\`. **ABAP:** ATC / Code Inspector checks.
- Agrega un script \`lint:security\` (o equivalente) en \`package.json\`/Makefile/\`build.gradle\`/\`pyproject.toml\`.

### C3. Pre-commit: escaneo de secretos
- Crea \`.gitleaks.toml\` con reglas para keys, tokens, connection strings y claves privadas.
- Configura un hook de pre-commit (\`husky\` + \`lint-staged\` en Node, o \`pre-commit\` framework) que corra gitleaks y el lint de seguridad antes de cada commit.

### C4. CI: puertas de seguridad (security gates)
Crea (si no existe) un workflow de CI (\`.github/workflows/security.yml\` o equivalente) que en cada push/PR:
1. Audite dependencias: \`npm audit --audit-level=high\` / \`pip-audit\` / \`osv-scanner\`.
2. Corra SAST: \`semgrep\` (config \`p/owasp-top-ten\` + \`p/security-audit\`) o CodeQL.
3. Escanee secretos: \`gitleaks detect\`.
4. Falle el build si aparecen hallazgos CRITICAL/HIGH.

### C5. Documentación e higiene
- Crea/actualiza \`SECURITY.md\`: política de secretos, dependencias, respuesta a vulnerabilidades y cómo correr los controles locales.
- Garantiza \`.env.example\` con placeholders vacíos y que \`.env\`, claves y archivos sensibles estén en \`.gitignore\`.

### Instrucciones para la Parte C
- Si un archivo/herramienta ya existe, mejóralo en lugar de duplicarlo.
- Indica los comandos exactos de instalación y cómo verificar que cada control funciona.
- Al final, lista los archivos de reglas/skills creados y los controles activados.

---

## VERIFICACIÓN POST-FIX

Después de aplicar todos los fixes:
1. Ejecuta el test suite completo y asegúrate de que nada se rompió
2. Verifica que no queden secretos en el código (grep por passwords, tokens, keys)
3. Confirma que las dependencias están actualizadas a versiones seguras
4. Verifica los controles de la Parte C: corre \`lint:security\`, \`gitleaks detect\` y confirma que los skills de IA y el workflow de CI existen y funcionan
5. El objetivo es que un re-escaneo de EATHERIA no reporte hallazgos CRITICAL, HIGH ni MEDIUM

## RESUMEN
- Hallazgos específicos a corregir (Parte A): ${actionableVulns.length} vulnerabilidades
- CRITICAL: ${actionableVulns.filter((v) => v.severity === "CRITICAL").length}
- HIGH: ${actionableVulns.filter((v) => v.severity === "HIGH").length}
- MEDIUM: ${actionableVulns.filter((v) => v.severity === "MEDIUM").length}
- Auditoría proactiva (Parte B): recorre TODO el proyecto con el checklist de 9 categorías y corrige lo que encuentres
- Blindaje futuro (Parte C): crea skills de IA + lint de seguridad + pre-commit (gitleaks) + CI gates + SECURITY.md
- Objetivo final: re-escaneo de EATHERIA sin hallazgos CRITICAL/HIGH/MEDIUM y controles activos para cambios futuros
`;

    return prompt;
  };

  const handleClick = () => {
    const prompt = generatePrompt();

    // If prompt is large (>40KB), download as .txt file
    if (prompt.length > 40000) {
      const blob = new Blob([prompt], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aetheria-fix-prompt-${analysis.appVersion.application.name.replace(/\s+/g, "-").toLowerCase()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      // Copy to clipboard
      navigator.clipboard.writeText(prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  return (
    <Button variant="outline" size="sm" onClick={handleClick} className="gap-1.5 border-purple-500/40 text-purple-400 hover:bg-purple-500/10 hover:text-purple-300">
      {copied ? <Check className="h-3.5 w-3.5" /> : <Sparkles className="h-3.5 w-3.5" />}
      {copied ? "Copiado!" : "AI Fix Prompt"}
    </Button>
  );
}

function FindingRow({ v, expanded, onToggle, knowledge, copiedFix, setCopiedFix }: {
  v: VulnData; expanded: boolean; onToggle: () => void;
  knowledge?: KnowledgeEntry;
  copiedFix: string | null; setCopiedFix: (id: string | null) => void;
}) {
  return (
    <div className={`rounded-lg border overflow-hidden transition-colors ${expanded ? "border-cyan-500/30 bg-card" : "border-border hover:border-border"}`}>
      {/* Row header */}
      <button onClick={onToggle} className="w-full flex items-center gap-2.5 px-3 py-2.5 text-left">
        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border shrink-0 ${SEV_COLORS[v.severity]}`}>{v.severity}</span>
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-medium text-text-primary truncate">{v.title}</p>
          <div className="flex items-center gap-2 mt-0.5 text-[10px] text-text-muted">
            <span>{v.category}</span>
            {v.cweId && <span className="text-cyan-500/70">{v.cweId}</span>}
            {v.filePath && <span className="flex items-center gap-0.5 truncate max-w-[160px]"><FileCode className="h-2.5 w-2.5" />{v.filePath}{v.lineStart ? `:${v.lineStart}` : ""}</span>}
          </div>
        </div>
        {v.detectionMethod && <Badge variant="outline" className="text-[8px] px-1 py-0 border-border text-text-muted shrink-0">{v.detectionMethod}</Badge>}
        {v.deltaStatus === "NEW" && <Badge className="text-[8px] bg-emerald-500/20 text-emerald-400 border-0 shrink-0">NEW</Badge>}
        {v.deltaStatus === "REOPENED" && <Badge className="text-[8px] bg-amber-500/20 text-amber-400 border-0 shrink-0">REOPENED</Badge>}
        {v.aiValidated && <Shield className="h-3.5 w-3.5 text-emerald-500 shrink-0" />}
        {v.isFalsePositive && <Badge variant="warning" className="text-[8px] shrink-0">FP</Badge>}
        {expanded ? <ChevronUp className="h-3.5 w-3.5 text-text-muted shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 text-text-muted shrink-0" />}
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-border space-y-4 pt-3">
          {/* Overview + Classification */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1">Descripción</h4>
              <p className="text-xs text-text-primary leading-relaxed">{v.description}</p>
              {v.rootCause && <p className="text-xs text-amber-300/80 mt-2"><AlertTriangle className="h-3 w-3 inline mr-1" />Causa raíz: {v.rootCause}</p>}
              {v.isFalsePositive && v.fpReason && <p className="text-xs text-text-muted mt-1 italic">FP: {v.fpReason}</p>}
            </div>
            <div className="space-y-2">
              <h4 className="text-[10px] font-semibold uppercase text-text-muted">Clasificación</h4>
              <div className="flex flex-wrap gap-2">
                {v.cweId && (
                  <a href={`https://cwe.mitre.org/data/definitions/${v.cweId.replace("CWE-", "")}.html`} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-accent text-[10px] hover:bg-cyan-500/20">
                    {v.cweId} <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
                {v.cveId && (
                  <a href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] hover:bg-red-500/20">
                    {v.cveId} <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
                {v.owaspTop10 && <span className="px-2 py-1 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 text-[10px]">{v.owaspTop10}</span>}
                {knowledge?.catalog?.rank && <span className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px]">MITRE Top 25 #{knowledge.catalog.rank}</span>}
                <span className="px-2 py-1 rounded bg-surface-hover border border-border text-text-secondary text-[10px]">Confianza: {v.confidence}</span>
              </div>
              {/* Compliance badges */}
              {knowledge?.compliance && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {knowledge.compliance.owasp2021 && <ComplianceBadge label={`OWASP ${knowledge.compliance.owasp2021}`} />}
                  {knowledge.compliance.pciDss && <ComplianceBadge label={`PCI ${knowledge.compliance.pciDss}`} />}
                  {knowledge.compliance.nist80053 && <ComplianceBadge label={`NIST ${knowledge.compliance.nist80053}`} />}
                  {knowledge.compliance.iso27001 && <ComplianceBadge label={`ISO ${knowledge.compliance.iso27001}`} />}
                  {knowledge.compliance.hipaa && <ComplianceBadge label={`HIPAA ${knowledge.compliance.hipaa}`} />}
                </div>
              )}
            </div>
          </div>

          {/* Root Causes from BugHunter */}
          {knowledge?.rootCauses && knowledge.rootCauses.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1.5">Causas Raíz (BugHunter)</h4>
              <ol className="list-decimal list-inside space-y-1">
                {knowledge.rootCauses.slice(0, 5).map((rc, i) => (
                  <li key={i} className="text-xs text-text-primary"><span className="font-medium text-text-primary">{rc.title}</span> — {rc.detail}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Impact Examples */}
          {knowledge?.impactExamples && knowledge.impactExamples.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1.5">Impacto Real (CVEs)</h4>
              <div className="space-y-1.5">
                {knowledge.impactExamples.slice(0, 3).map((ie, i) => (
                  <div key={i} className="text-xs text-text-secondary bg-surface rounded px-2.5 py-1.5">
                    <span className="text-text-primary font-medium">{ie.scenario}</span>
                    {ie.cveIds.length > 0 && <span className="ml-2 text-red-400">{ie.cveIds.join(", ")}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Code snippet */}
          {v.codeSnippet && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1">Código</h4>
              <pre className="rounded-lg bg-background border border-border p-3 text-[11px] text-text-primary overflow-x-auto max-h-48"><code>{v.codeSnippet}</code></pre>
            </div>
          )}

          {/* Remediation */}
          {knowledge?.catalog?.remediation && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1">Remediación</h4>
              <p className="text-xs text-text-primary">{knowledge.catalog.remediation}</p>
            </div>
          )}

          {/* Smart Fix */}
          {v.smartFix && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <h4 className="text-[10px] font-semibold uppercase text-text-muted flex items-center gap-1"><Wrench className="h-3 w-3" /> Fix IA</h4>
                <button onClick={() => { navigator.clipboard.writeText(v.smartFix || ""); setCopiedFix(v.id); setTimeout(() => setCopiedFix(null), 2000); }}
                  className="flex items-center gap-1 text-[10px] text-accent hover:text-accent">
                  {copiedFix === v.id ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  {copiedFix === v.id ? "Copiado" : "Copiar"}
                </button>
              </div>
              <pre className="rounded-lg bg-emerald-500/10 border border-emerald-600/40 p-3 text-[11px] text-emerald-800 dark:bg-emerald-950/30 dark:border-emerald-800/30 dark:text-emerald-300 overflow-x-auto max-h-64"><code>{v.smartFix}</code></pre>
              {v.fixExplanation && <p className="text-[11px] text-text-secondary mt-1">{v.fixExplanation}</p>}
            </div>
          )}

          {/* Attack Chains */}
          {knowledge?.chains && knowledge.chains.length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1.5">Cadenas de Ataque</h4>
              <div className="space-y-1">
                {knowledge.chains.slice(0, 4).map((ch, i) => (
                  <p key={i} className="text-[11px] text-text-secondary"><span className="text-accent font-mono">{ch.targetSkill}</span> — {ch.primitive}</p>
                ))}
              </div>
            </div>
          )}

          {/* References */}
          {knowledge?.catalog?.references && (knowledge.catalog.references as string[]).length > 0 && (
            <div>
              <h4 className="text-[10px] font-semibold uppercase text-text-muted mb-1">Referencias</h4>
              <div className="flex flex-wrap gap-2">
                {(knowledge.catalog.references as string[]).slice(0, 5).map((ref, i) => (
                  <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-[10px] text-accent hover:underline truncate max-w-[200px]">{ref}</a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ComplianceBadge({ label }: { label: string }) {
  return <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 text-[9px] font-medium">{label}</span>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function pushStandard(standards: Record<string, { requirement: string; count: number }[]>, standard: string, requirement: string) {
  if (!standards[standard]) standards[standard] = [];
  const existing = standards[standard].find((r) => r.requirement === requirement);
  if (existing) existing.count++;
  else standards[standard].push({ requirement, count: 1 });
}

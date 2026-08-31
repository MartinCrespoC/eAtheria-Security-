"use client";

/**
 * Unified Industry-Standards dashboard.
 *
 * Renders every `BenchmarkRun` in two flavours:
 *   • DETECTION benchmarks (kind="detection") — OWASP / CVE / Juliet / WSTG /
 *     curated. Each source gets a scorecard card (TPR / FPR / OWASP Score +
 *     per-category breakdown + run history).
 *   • ASSESSMENTS (kind="assessment") — OpenSSF Scorecard (0–10 per check) and
 *     OpenSSF Best Practices Badge (tier % + actionable gaps).
 *
 * A kind toggle + source chips (reusing the admin source-filter pattern) let the
 * user focus on one standard at a time.
 */
import { useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import {
  Award,
  ShieldCheck,
  Target,
  Activity,
  CheckCircle2,
  XCircle,
  MinusCircle,
  FlaskConical,
  Gauge,
  Download,
} from "lucide-react";

export interface BenchmarkRunDTO {
  id: string;
  name: string;
  source: string;
  kind: string;
  totalCases: number;
  tpr: number;
  fpr: number;
  precision: number;
  recall: number;
  score: number;
  byCategory: Record<string, unknown> | null;
  metrics: Record<string, unknown> | null;
  createdAt: string;
}

interface CategoryScoreDTO {
  total?: number;
  tp?: number;
  fp?: number;
  tn?: number;
  fn?: number;
  tpr?: number;
  fpr?: number;
  precision?: number;
  recall?: number;
  score?: number;
}

interface ScorecardCheckDTO {
  name: string;
  score: number;
  reason: string;
}

interface BadgeTierDTO {
  met: number;
  unmet: number;
  na: number;
  total: number;
  pct: number;
}

interface BadgeCriterionDTO {
  id: string;
  tier: string;
  majorGroup: string;
  category: string;
  result: "met" | "unmet" | "na";
}

const SOURCE_LABELS: Record<string, string> = {
  curated: "Curated",
  owasp: "OWASP (lite)",
  "owasp-full": "OWASP Benchmark",
  juliet: "NIST Juliet",
  wstg: "OWASP WSTG",
  "cve-benchmark": "OpenSSF CVE",
  scorecard: "OpenSSF Scorecard",
  "best-practices-badge": "Best Practices Badge",
};

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const sourceLabel = (s: string) => SOURCE_LABELS[s] ?? s;
const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });

/** Color for an OWASP score / rate (green = good, red = bad). */
function scoreColor(n: number): string {
  if (n >= 0.8) return "text-emerald-400";
  if (n >= 0.5) return "text-lime-400";
  if (n >= 0.2) return "text-amber-400";
  return "text-red-400";
}

function barColor(n: number): string {
  if (n >= 0.8) return "bg-emerald-500";
  if (n >= 0.5) return "bg-lime-500";
  if (n >= 0.2) return "bg-amber-500";
  return "bg-red-500";
}

/** Sum the per-category confusion counts into an overall accuracy figure. */
function detectionOverall(run: BenchmarkRunDTO) {
  const by = (run.byCategory ?? {}) as Record<string, CategoryScoreDTO>;
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0,
    total = 0;
  for (const cat of Object.values(by)) {
    tp += cat.tp ?? 0;
    fp += cat.fp ?? 0;
    tn += cat.tn ?? 0;
    fn += cat.fn ?? 0;
    total += cat.total ?? 0;
  }
  return { tp, fp, tn, fn, total, accuracy: total ? (tp + tn) / total : 0 };
}

// ─────────────────────────── detection card ───────────────────────────

function DetectionCard({ source, runs }: { source: string; runs: BenchmarkRunDTO[] }) {
  const latest = runs[0];
  const history = runs.slice(0, 6);
  const overall = detectionOverall(latest);
  const categories = Object.entries(
    (latest.byCategory ?? {}) as Record<string, CategoryScoreDTO>
  ).sort((a, b) => a[0].localeCompare(b[0]));

  return (
    <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <Target className="h-4 w-4 text-text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">{sourceLabel(source)}</h3>
            <p className="text-xs text-text-secondary">{fmtDate(latest.createdAt)}</p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <span className="text-xs text-text-muted">{latest.totalCases} casos</span>
          <EvidenceButtons runId={latest.id} />
        </div>
      </div>

      {/* headline metrics */}
      <div className="grid grid-cols-4 gap-2">
        <Metric label="Score" value={pct(latest.score)} valueClass={scoreColor(latest.score + 1 / 2)} sub="TPR−FPR" />
        <Metric label="TPR" value={pct(latest.tpr)} valueClass="text-emerald-400" sub="recall" />
        <Metric label="FPR" value={pct(latest.fpr)} valueClass={latest.fpr <= 0.1 ? "text-emerald-400" : "text-red-400"} sub="lower=better" />
        <Metric label="Accuracy" value={pct(overall.accuracy)} valueClass="text-text-primary" sub={`${overall.tp + overall.tn}/${overall.total}`} />
      </div>

      {/* per-category breakdown */}
      {categories.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead className="bg-surface text-text-secondary">
              <tr>
                <th className="px-3 py-1.5 text-left font-medium">Categoría</th>
                <th className="px-3 py-1.5 text-right font-medium">Total</th>
                <th className="px-3 py-1.5 text-right font-medium">TPR</th>
                <th className="px-3 py-1.5 text-right font-medium">FPR</th>
                <th className="px-3 py-1.5 text-right font-medium">Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {categories.map(([name, c]) => (
                <tr key={name} className="text-text-primary">
                  <td className="px-3 py-1.5">{name}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{c.total ?? 0}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums text-emerald-400">{pct(c.tpr ?? 0)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums text-red-400">{pct(c.fpr ?? 0)}</td>
                  <td className={cn("px-3 py-1.5 text-right tabular-nums", scoreColor((c.score ?? 0) + 1 / 2))}>{pct(c.score ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* run history */}
      {history.length > 1 && (
        <div>
          <p className="text-xs font-medium text-text-secondary mb-1.5">Historial ({runs.length} ejecuciones)</p>
          <div className="space-y-1">
            {history.map((r) => (
              <div key={r.id} className="flex items-center gap-2 text-xs">
                <span className="w-32 shrink-0 text-text-muted">{fmtDate(r.createdAt)}</span>
                <div className="flex-1 h-1.5 rounded-full bg-surface-hover overflow-hidden">
                  <div
                    className={cn("h-full rounded-full", barColor((r.score + 1) / 2))}
                    style={{ width: `${Math.max(0, Math.min(100, ((r.score + 1) / 2) * 100))}%` }}
                  />
                </div>
                <span className={cn("w-14 text-right tabular-nums", scoreColor(r.score + 1 / 2))}>{pct(r.score)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function EvidenceButtons({ runId }: { runId: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <a
        href={`/api/standards/evidence?runId=${runId}&format=json`}
        download
        className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-hover px-2 py-1 text-[10px] font-medium text-text-secondary hover:text-accent hover:border-cyan-500/40 transition-colors"
        title="Descargar evidencia clasificada (JSON)"
      >
        <Download className="h-3 w-3" /> JSON
      </a>
      <a
        href={`/api/standards/evidence?runId=${runId}&format=csv`}
        download
        className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-hover px-2 py-1 text-[10px] font-medium text-text-secondary hover:text-accent hover:border-cyan-500/40 transition-colors"
        title="Descargar evidencia clasificada (CSV)"
      >
        <Download className="h-3 w-3" /> CSV
      </a>
    </div>
  );
}

function Metric({ label, value, sub, valueClass }: { label: string; value: string; sub?: string; valueClass?: string }) {
  return (
    <div className="rounded-lg bg-card border border-border px-2 py-2 text-center">
      <p className="text-[10px] uppercase tracking-wider text-text-muted">{label}</p>
      <p className={cn("text-lg font-bold tabular-nums", valueClass ?? "text-text-primary")}>{value}</p>
      {sub && <p className="text-[10px] text-text-muted">{sub}</p>}
    </div>
  );
}

// ─────────────────────────── scorecard card ───────────────────────────

function ScorecardCard({ run }: { run: BenchmarkRunDTO }) {
  const m = (run.metrics ?? {}) as Record<string, unknown>;
  const checks = (m.checks as ScorecardCheckDTO[] | undefined) ?? [];
  const overall10 = typeof m.overallScore10 === "number" ? m.overallScore10 : run.score * 10;
  const repo = typeof m.repo === "string" ? m.repo : "";
  const acquisition = typeof m.acquisition === "string" ? m.acquisition : "";

  return (
    <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center">
            <Gauge className="h-4 w-4 text-text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">OpenSSF Scorecard</h3>
            <p className="text-xs text-text-secondary">{repo || "repositorio"}{acquisition ? ` · ${acquisition}` : ""}</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold tabular-nums text-text-primary">{overall10.toFixed(1)}<span className="text-sm text-text-muted">/10</span></p>
          <p className="text-xs text-text-muted">{fmtDate(run.createdAt)}</p>
          <div className="mt-1.5 flex justify-end"><EvidenceButtons runId={run.id} /></div>
        </div>
      </div>

      <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
        {checks.map((c) => (
          <div key={c.name} className="flex items-center gap-2 text-xs">
            <span className="w-40 shrink-0 text-text-primary truncate" title={c.name}>{c.name}</span>
            <div className="flex-1 h-1.5 rounded-full bg-surface-hover overflow-hidden">
              <div
                className={cn("h-full rounded-full", c.score < 0 ? "bg-surface-hover" : barColor(c.score / 10))}
                style={{ width: `${c.score < 0 ? 0 : c.score * 10}%` }}
              />
            </div>
            <span className={cn("w-10 text-right tabular-nums", c.score < 0 ? "text-text-muted" : scoreColor(c.score / 10))}>
              {c.score < 0 ? "?" : c.score}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────── badge card ───────────────────────────

function BadgeCard({ run }: { run: BenchmarkRunDTO }) {
  const m = (run.metrics ?? {}) as Record<string, unknown>;
  const tiers = (m.tiers as Record<string, BadgeTierDTO> | undefined) ?? {};
  const headlineTier = typeof m.headlineTier === "string" ? m.headlineTier : "passing";
  const criteria = (m.criteriaResults as BadgeCriterionDTO[] | undefined) ?? [];
  const unmet = criteria.filter((c) => c.result === "unmet");
  const tierOrder = ["passing", "silver", "gold"];

  return (
    <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center">
            <Award className="h-4 w-4 text-text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">Best Practices Badge</h3>
            <p className="text-xs text-text-secondary">nivel destacado: {headlineTier}</p>
          </div>
        </div>
        <p className="text-xs text-text-muted">{fmtDate(run.createdAt)}</p>
      </div>

      {/* tier progress */}
      <div className="space-y-2">
        {tierOrder.map((t) => {
          const s = tiers[t];
          if (!s) return null;
          return (
            <div key={t} className="text-xs">
              <div className="flex items-center justify-between mb-0.5">
                <span className="capitalize text-text-primary">{t}</span>
                <span className={cn("tabular-nums font-medium", scoreColor(s.pct / 100))}>
                  {s.pct.toFixed(1)}% <span className="text-text-muted">({s.met}/{s.met + s.unmet})</span>
                </span>
              </div>
              <div className="h-2 rounded-full bg-surface-hover overflow-hidden">
                <div className={cn("h-full rounded-full", barColor(s.pct / 100))} style={{ width: `${s.pct}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* actionable gaps */}
      {unmet.length > 0 && (
        <div>
          <p className="text-xs font-medium text-text-secondary mb-1.5">Brechas detectadas ({unmet.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {unmet.map((u) => (
              <span
                key={`${u.tier}|${u.id}`}
                className="inline-flex items-center gap-1 rounded-md bg-red-500/10 border border-red-500/20 px-2 py-0.5 text-[11px] text-red-300"
                title={`[${u.tier}/${u.majorGroup}] ${u.category}`}
              >
                <XCircle className="h-3 w-3" />
                {u.id}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────── main component ───────────────────────────

type KindFilter = "all" | "detection" | "assessment";

export function StandardsDashboard({ runs }: { runs: BenchmarkRunDTO[] }) {
  const [kind, setKind] = useState<KindFilter>("all");
  const [source, setSource] = useState<string>("all");

  // Group runs by source (runs arrive sorted desc by createdAt).
  const bySource = useMemo(() => {
    const map = new Map<string, BenchmarkRunDTO[]>();
    for (const r of runs) {
      const list = map.get(r.source) ?? [];
      list.push(r);
      map.set(r.source, list);
    }
    return map;
  }, [runs]);

  const sources = useMemo(
    () =>
      Array.from(bySource.entries())
        .map(([s, list]) => ({ source: s, kind: list[0].kind, latest: list[0] }))
        .sort((a, b) => a.source.localeCompare(b.source)),
    [bySource]
  );

  const visibleSources = sources.filter((s) => {
    if (kind !== "all" && s.kind !== kind) return false;
    if (source !== "all" && s.source !== source) return false;
    return true;
  });

  const detectionSources = visibleSources.filter((s) => s.kind === "detection");
  const assessmentSources = visibleSources.filter((s) => s.kind === "assessment");

  const kindTabs: { key: KindFilter; label: string }[] = [
    { key: "all", label: "Todos" },
    { key: "detection", label: "Detección" },
    { key: "assessment", label: "Evaluación" },
  ];

  return (
    <div className="space-y-6">
      {/* filter bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="inline-flex rounded-lg border border-border bg-surface p-1">
          {kindTabs.map((t) => (
            <button
              key={t.key}
              onClick={() => {
                setKind(t.key);
                setSource("all");
              }}
              className={cn(
                "px-3 py-1.5 text-sm rounded-md transition-colors",
                kind === t.key ? "bg-cyan-500/20 text-accent" : "text-text-secondary hover:text-text-primary"
              )}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => setSource("all")}
            className={cn(
              "px-2.5 py-1 text-xs rounded-md border transition-colors",
              source === "all"
                ? "bg-surface-hover border-border text-text-primary"
                : "border-border text-text-secondary hover:text-text-primary"
            )}
          >
            Todas las fuentes
          </button>
          {sources
            .filter((s) => kind === "all" || s.kind === kind)
            .map((s) => (
              <button
                key={s.source}
                onClick={() => setSource(source === s.source ? "all" : s.source)}
                className={cn(
                  "px-2.5 py-1 text-xs rounded-md border transition-colors",
                  source === s.source
                    ? "bg-cyan-500/20 border-cyan-500/40 text-accent"
                    : "border-border text-text-secondary hover:text-text-primary"
                )}
              >
                {sourceLabel(s.source)}
              </button>
            ))}
        </div>
      </div>

      {runs.length === 0 && (
        <div className="rounded-xl border border-dashed border-border bg-surface p-10 text-center">
          <FlaskConical className="h-10 w-10 text-text-muted mx-auto mb-3" />
          <p className="text-text-primary font-medium">No benchmarks yet</p>
          <p className="text-sm text-text-muted mt-1">
            Industry-standard evaluations (OWASP, CVE, WSTG) run automatically on the
            platform. Results will appear here once the first benchmark cycle completes.
          </p>
        </div>
      )}

      {/* detection scorecards */}
      {detectionSources.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-accent" />
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-primary">
              Benchmarks de detección (TPR/FPR)
            </h2>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {detectionSources.map((s) => (
              <DetectionCard key={s.source} source={s.source} runs={bySource.get(s.source)!} />
            ))}
          </div>
        </section>
      )}

      {/* assessments */}
      {assessmentSources.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-purple-400" />
            <h2 className="text-sm font-semibold uppercase tracking-wider text-text-primary">
              Evaluaciones de postura (assessment)
            </h2>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {assessmentSources.map((s) => {
              const latest = bySource.get(s.source)![0];
              return s.source === "scorecard" ? (
                <ScorecardCard key={s.source} run={latest} />
              ) : s.source === "best-practices-badge" ? (
                <BadgeCard key={s.source} run={latest} />
              ) : (
                <DetectionCard key={s.source} source={s.source} runs={bySource.get(s.source)!} />
              );
            })}
          </div>
        </section>
      )}

      {/* legend */}
      {runs.length > 0 && (
        <div className="flex flex-wrap items-center gap-4 text-xs text-text-muted">
          <span className="inline-flex items-center gap-1"><CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> TP: vulnerabilidad real retenida</span>
          <span className="inline-flex items-center gap-1"><MinusCircle className="h-3.5 w-3.5 text-text-secondary" /> TN: código seguro descartado</span>
          <span>Score OWASP = TPR − FPR</span>
        </div>
      )}
    </div>
  );
}

/**
 * Benchmark scorecard — OWASP-Benchmark-style metrics.
 *
 * Our detector is a FALSE-POSITIVE FILTER: given a finding already raised by
 * SAST/AI, it decides whether to keep it (detected = "TP") or dismiss it as a
 * false positive (detected = "FP"). Against labeled cases:
 *   - expected "TP" = a REAL vulnerability (must be kept)
 *   - expected "FP" = safe code a naive tool flagged (must be dismissed)
 *
 * Confusion matrix (rows = expected, cols = detected):
 *                 detected TP   detected FP
 *   expected TP      TP            FN   (FN = real vuln wrongly dismissed)
 *   expected FP      FP            TN   (FP = safe code wrongly kept)
 *
 * Metrics:
 *   TPR (recall) = TP / (TP + FN)        — real vulns we correctly kept
 *   FPR          = FP / (FP + TN)        — safe code we wrongly kept (lower = better)
 *   Precision    = TP / (TP + FP)
 *   Score (OWASP) = TPR - FPR            — single comparable number (-1..1)
 */

export interface CaseResult {
  cweId: string;
  category: string;
  expected: "TP" | "FP";
  detected: "TP" | "FP";
  correct: boolean;
}

export interface CategoryScore {
  total: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  tpr: number;
  fpr: number;
  precision: number;
  recall: number;
  score: number;
}

function scoreGroup(results: CaseResult[]): CategoryScore {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const r of results) {
    if (r.expected === "TP" && r.detected === "TP") tp++;
    else if (r.expected === "TP" && r.detected === "FP") fn++;
    else if (r.expected === "FP" && r.detected === "TP") fp++;
    else if (r.expected === "FP" && r.detected === "FP") tn++;
  }
  const tpr = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  return {
    total: results.length,
    tp,
    fp,
    tn,
    fn,
    tpr,
    fpr,
    precision,
    recall: tpr,
    score: tpr - fpr,
  };
}

export interface Scorecard {
  overall: CategoryScore;
  byCategory: Record<string, CategoryScore>;
}

export function computeScores(results: CaseResult[]): Scorecard {
  const grouped: Record<string, CaseResult[]> = {};
  for (const r of results) {
    (grouped[r.category] ??= []).push(r);
  }
  const byCategory: Record<string, CategoryScore> = {};
  for (const [category, rs] of Object.entries(grouped)) {
    byCategory[category] = scoreGroup(rs);
  }
  return { overall: scoreGroup(results), byCategory };
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`;

/** Print a comparative console table for a scorecard. */
export function printScorecard(card: Scorecard): void {
  const rows: [string, CategoryScore][] = [
    ...Object.entries(card.byCategory).sort((a, b) => a[0].localeCompare(b[0])),
    ["OVERALL", card.overall],
  ];
  console.log("\n┌─────────────────────┬───────┬────────┬────────┬─────────┬────────┬─────────┐");
  console.log("│ Category            │ Total │  TPR   │  FPR   │ Prec.   │ Recall │  Score  │");
  console.log("├─────────────────────┼───────┼────────┼────────┼─────────┼────────┼─────────┤");
  for (const [name, s] of rows) {
    const label = name.padEnd(19).slice(0, 19);
    const total = String(s.total).padStart(5);
    console.log(
      `│ ${label} │ ${total} │ ${pct(s.tpr).padStart(6)} │ ${pct(s.fpr).padStart(6)} │ ${pct(
        s.precision
      ).padStart(7)} │ ${pct(s.recall).padStart(6)} │ ${pct(s.score).padStart(7)} │`
    );
  }
  console.log("└─────────────────────┴───────┴────────┴────────┴─────────┴────────┴─────────┘");
  const o = card.overall;
  console.log(
    `   Confusion: TP=${o.tp} FN=${o.fn} (real vulns) · FP=${o.fp} TN=${o.tn} (safe code)`
  );
}

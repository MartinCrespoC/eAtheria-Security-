/**
 * Curated benchmark cases — a small, always-available labeled dataset.
 *
 * Each entry is a code snippet plus the ground-truth label:
 *   expected "TP" = a REAL vulnerability the detector must KEEP (not dismiss)
 *   expected "FP" = safe code the detector must DISMISS as a false positive
 *
 * These exercise the deterministic detector (builtin rules + ingested gitleaks
 * patterns + DB language patterns). They give a stable baseline so the harness
 * runs out-of-the-box and can demonstrate FPR reduction before/after ingesting
 * external knowledge, without requiring the (large, licensed) OWASP/Juliet sets.
 */
import type { BenchmarkCaseInput } from "../../../src/lib/knowledge/fp-sync/types";

export const CURATED_BENCHMARK_CASES: BenchmarkCaseInput[] = [
  // ── CWE-798 Hard-coded Credentials ─────────────────────────────────────────
  {
    cweId: "CWE-798", category: "secret", expected: "FP", language: "javascript",
    snippet: "const apiKey = process.env.API_KEY;",
  },
  {
    cweId: "CWE-798", category: "secret", expected: "FP", language: "javascript",
    snippet: "const token = configService.get('JWT_SECRET');",
  },
  {
    // Caught by an INGESTED gitleaks allowlist (GitHub Actions secret expression).
    cweId: "CWE-798", category: "secret", expected: "FP", language: "javascript",
    snippet: "${{ secrets.DEPLOY_TOKEN }}",
  },
  {
    cweId: "CWE-798", category: "secret", expected: "TP", language: "javascript",
    snippet: 'const apiKey = "AKIAIOSFODNN7REALKEY123";',
  },
  {
    cweId: "CWE-798", category: "secret", expected: "TP", language: "python",
    snippet: 'password = "Sup3rS3cretProdP@ss!"',
  },

  // ── CWE-79 Cross-Site Scripting ────────────────────────────────────────────
  {
    cweId: "CWE-79", category: "xss", expected: "FP", language: "javascript",
    snippet: 'document.getElementById("banner").innerHTML = "<svg width=\'120\'></svg>";',
  },
  {
    cweId: "CWE-79", category: "xss", expected: "TP", language: "javascript",
    snippet: "container.innerHTML = comment.bodyHtml;",
  },

  // ── CWE-601 Open Redirect ──────────────────────────────────────────────────
  {
    cweId: "CWE-601", category: "open-redirect", expected: "FP", language: "javascript",
    snippet: "if (isTrustedTarget(returnUrl)) { res.redirect(returnUrl); }",
  },
  {
    cweId: "CWE-601", category: "open-redirect", expected: "TP", language: "javascript",
    snippet: "res.redirect(req.query.next);",
  },

  // ── CWE-22 Path Traversal ──────────────────────────────────────────────────
  {
    cweId: "CWE-22", category: "path-traversal", expected: "FP", language: "javascript",
    snippet: 'const configPath = path.join(__dirname, "config.json");',
  },
  {
    cweId: "CWE-22", category: "path-traversal", expected: "TP", language: "javascript",
    snippet: 'const filePath = "/data/" + req.params.name;',
  },

  // ── CWE-89 SQL Injection ───────────────────────────────────────────────────
  {
    cweId: "CWE-89", category: "sqli", expected: "FP", language: "go",
    snippet: 'db := sql.DB{}; db.Query("SELECT name FROM users WHERE id = $1", id)',
  },
  {
    cweId: "CWE-89", category: "sqli", expected: "TP", language: "go",
    snippet: 'db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")',
  },

  // ── CWE-78 OS Command Injection ────────────────────────────────────────────
  {
    cweId: "CWE-78", category: "command-injection", expected: "FP", language: "python",
    snippet: 'subprocess.run(["ls", "-la", directory])',
  },
  {
    cweId: "CWE-78", category: "command-injection", expected: "TP", language: "python",
    snippet: "subprocess.run(user_cmd, shell=True)",
  },
];

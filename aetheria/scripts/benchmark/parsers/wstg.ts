/**
 * OWASP WSTG — detection benchmark cases.
 *
 * Derives labeled detection cases from the WSTG tests that map to CWEs our
 * engines detect. For every such CWE we emit one canonical *vulnerable* snippet
 * (expected "TP" — the detector must keep it) and one *safe* snippet (expected
 * "FP" — the detector must dismiss it), mirroring the curated/OWASP/Juliet case
 * shape so scores are comparable across sources.
 *
 * The WSTG→CWE mapping and document index come from the WSTG adapter
 * (`src/lib/knowledge/fp-sync/adapters/wstg.ts`); this module adds the code
 * templates. CWEs that WSTG covers but we have no reliable template for (e.g.
 * LDAP/XPath injection, CSRF) are skipped here — they remain in the knowledge
 * layer but are not scored.
 */
import type { BenchmarkCaseInput } from "../../../src/lib/knowledge/fp-sync/types";
import { parseWstgDocuments, cwesForDocument } from "../../../src/lib/knowledge/fp-sync/adapters/wstg";

interface CweTemplate {
  category: string;
  language: string;
  /** Canonical vulnerable snippet (expected TP). */
  tp: string;
  /** Canonical safe snippet (expected FP). */
  fp: string;
}

/**
 * Canonical vulnerable/safe pairs per CWE, written against our engine's sink
 * patterns (taint + secrets + IaC). Only CWEs we can reliably detect belong here.
 */
const CWE_TEMPLATES: Record<string, CweTemplate> = {
  "CWE-79": {
    category: "xss",
    language: "javascript",
    tp: "element.innerHTML = userComment.body;",
    fp: "element.textContent = userComment.body;",
  },
  "CWE-89": {
    category: "sqli",
    language: "javascript",
    tp: 'db.query("SELECT * FROM users WHERE id = " + req.params.id);',
    fp: 'db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);',
  },
  "CWE-78": {
    category: "command-injection",
    language: "javascript",
    tp: 'child_process.exec("ping " + req.query.host);',
    fp: 'child_process.execSync("ping -c 1 localhost");',
  },
  "CWE-22": {
    category: "path-traversal",
    language: "javascript",
    tp: 'fs.readFileSync("/data/" + req.params.name);',
    fp: 'fs.readFileSync("./config/default.json", "utf8");',
  },
  "CWE-601": {
    category: "open-redirect",
    language: "javascript",
    tp: "res.redirect(req.query.url);",
    fp: 'res.redirect("/dashboard");',
  },
  "CWE-918": {
    category: "ssrf",
    language: "javascript",
    tp: "fetch(req.body.webhookUrl);",
    fp: 'fetch("https://api.internal.example.com/health");',
  },
  "CWE-94": {
    category: "code-injection",
    language: "javascript",
    tp: "eval(req.query.expression);",
    fp: "JSON.parse(req.body.payload);",
  },
  "CWE-327": {
    category: "crypto",
    language: "javascript",
    tp: 'crypto.createHash("md5").update(password).digest("hex");',
    fp: 'crypto.createHash("sha256").update(data).digest("hex");',
  },
  "CWE-611": {
    category: "xxe",
    language: "javascript",
    tp: "libxmljs.parseXml(xmlData, { noent: true, dtdload: true });",
    fp: "libxmljs.parseXml(xmlData, { noent: false, nonet: true });",
  },
  "CWE-502": {
    category: "deserialization",
    language: "javascript",
    tp: "unserialize(req.cookies.sessionData);",
    fp: "JSON.parse(req.cookies.sessionData);",
  },
  "CWE-1336": {
    category: "ssti",
    language: "python",
    tp: 'render_template_string("Hello " + request.args.get("name"))',
    fp: 'render_template("index.html", name=escape(user_name))',
  },
  "CWE-1321": {
    category: "prototype-pollution",
    language: "javascript",
    tp: "_.merge(config, req.body.options);",
    fp: 'const merged = { ...defaults, theme: "dark" };',
  },
};

/**
 * Build the WSTG detection case set: one TP + one FP per CWE that WSTG covers
 * and we have a reliable template for. Returns the cases plus a small summary
 * (via the module-level `lastWstgSummary`) for reporting.
 */
export interface WstgCaseSummary {
  wstgTests: number;
  cwesCovered: number;
  cwesScored: number;
}

export let lastWstgSummary: WstgCaseSummary = { wstgTests: 0, cwesCovered: 0, cwesScored: 0 };

export async function parseWstgCases(): Promise<BenchmarkCaseInput[]> {
  const docs = parseWstgDocuments();

  // Collect the unique CWEs that WSTG tests map to.
  const covered = new Set<string>();
  for (const doc of docs) {
    for (const cwe of cwesForDocument(doc)) covered.add(cwe);
  }

  const cases: BenchmarkCaseInput[] = [];
  let scored = 0;
  for (const cwe of covered) {
    const tpl = CWE_TEMPLATES[cwe];
    if (!tpl) continue; // covered by WSTG but not reliably detectable by us
    scored++;
    cases.push({ cweId: cwe, category: tpl.category, expected: "TP", snippet: tpl.tp, language: tpl.language });
    cases.push({ cweId: cwe, category: tpl.category, expected: "FP", snippet: tpl.fp, language: tpl.language });
  }

  lastWstgSummary = { wstgTests: docs.length, cwesCovered: covered.size, cwesScored: scored };
  return cases;
}

/**
 * FP Knowledge System — OWASP WSTG adapter (knowledge + checklist).
 *
 * The OWASP Web Security Testing Guide (https://owasp.org/wstg) is the de-facto
 * manual for testing web applications. Each test is a markdown document with a
 * stable id (`WSTG-<CAT>-NN`), a title, a Summary and (sometimes) explicit CWE
 * references. This adapter clones the `OWASP/wstg` repo, parses those documents
 * and maps them to CWEs, producing two things:
 *
 *   1. CWE KNOWLEDGE — for every WSTG test that maps to a CWE, a short
 *      "how to test" guidance line is merged into `CweKnowledge.detectionGuidance`
 *      (via `parseCweKnowledge()`), feeding the AI detector context and giving
 *      humans a pointer to the canonical test procedure.
 *   2. A parsed document index (`parseWstgDocuments()`) that the WSTG detection
 *      benchmark (`scripts/benchmark/parsers/wstg.ts`) turns into labeled cases.
 *
 * Inline CWE references in the markdown are sparse (~13 files), so the mapping
 * below combines them with a curated, well-established WSTG→CWE table for the
 * tests that correspond to CWEs our engines detect.
 */
import * as fs from "fs";
import * as path from "path";
import { VENDOR_ROOT, ensureGitRepo } from "../orchestrator";
import type { FpSourceAdapter, NormalizedCweKnowledge, NormalizedFpPattern } from "../types";

export const WSTG_REPO = "https://github.com/OWASP/wstg.git";
export const WSTG_DIR = path.join(VENDOR_ROOT, "wstg");
export const WSTG_TESTING_DIR = path.join(WSTG_DIR, "document", "4-Web_Application_Security_Testing");

export interface WstgDocument {
  /** Stable test id, e.g. `WSTG-INPV-05`. */
  id: string;
  title: string;
  /** First ~240 chars of the Summary section. */
  summary: string;
  /** CWE ids referenced inline in the markdown (e.g. `CWE-78`). */
  inlineCwes: string[];
  /** Relative path of the markdown file under the testing chapter. */
  file: string;
}

/**
 * Curated WSTG test → CWE mapping, focused on the CWEs our detection engines
 * cover. These are well-established correspondences (WSTG test names map 1:1 to
 * the weakness classes). Combined with inline references at parse time.
 */
export const WSTG_TO_CWES: Record<string, string[]> = {
  "WSTG-INPV-01": ["CWE-79"], // Reflected XSS
  "WSTG-INPV-02": ["CWE-79"], // Stored XSS
  "WSTG-CLNT-01": ["CWE-79"], // DOM-based XSS
  "WSTG-CLNT-03": ["CWE-79"], // HTML Injection
  "WSTG-INPV-05": ["CWE-89"], // SQL Injection
  "WSTG-INPV-06": ["CWE-90"], // LDAP Injection
  "WSTG-INPV-07": ["CWE-611"], // XML Injection / XXE
  "WSTG-INPV-09": ["CWE-643"], // XPath Injection
  "WSTG-INPV-11": ["CWE-94"], // Code Injection
  "WSTG-INPV-12": ["CWE-78"], // Command Injection
  "WSTG-INPV-18": ["CWE-1336"], // Server-side Template Injection
  "WSTG-INPV-19": ["CWE-918"], // SSRF
  "WSTG-INPV-22": ["CWE-1321"], // Prototype Pollution
  "WSTG-ATHZ-01": ["CWE-22"], // Directory Traversal / File Include
  "WSTG-CLNT-04": ["CWE-601"], // Client-side URL Redirect
  "WSTG-CRYP-04": ["CWE-327"], // Weak Cryptographic Primitives
  "WSTG-SESS-05": ["CWE-352"], // CSRF
  "WSTG-INPV-08": ["CWE-97"], // SSI Injection
};

/** Canonical CWE names for the mapped CWEs (kept stable so we never clobber MITRE names). */
export const CWE_NAMES: Record<string, string> = {
  "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
  "CWE-611": "Improper Restriction of XML External Entity Reference ('XXE')",
  "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
  "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
  "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
  "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
  "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-97": "Improper Neutralization of Server-Side Includes (SSI) Within a Web Page",
};

/** Extract the WSTG id, title and a short summary from a markdown document. */
function parseWstgMarkdown(content: string, relFile: string): WstgDocument | null {
  const idMatch = content.match(/WSTG-[A-Z]+-\d+(?:\.\d+)?/);
  if (!idMatch) return null;
  const id = idMatch[0];

  const titleMatch = content.match(/^#\s+(.+)$/m);
  const title = titleMatch ? titleMatch[1].trim() : id;

  // Summary = text under "## Summary" up to the next "## " heading.
  let summary = "";
  const sumIdx = content.indexOf("## Summary");
  if (sumIdx >= 0) {
    const rest = content.slice(sumIdx + "## Summary".length);
    const nextHeading = rest.indexOf("\n## ");
    const block = nextHeading >= 0 ? rest.slice(0, nextHeading) : rest;
    summary = block
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1") // strip links → text
      .replace(/[`*_>#|]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 240);
  }

  const inlineCwes = Array.from(
    new Set(Array.from(content.matchAll(/CWE-(\d+)/g)).map((m) => `CWE-${parseInt(m[1], 10)}`))
  );

  return { id, title, summary, inlineCwes, file: relFile };
}

/** Walk the testing chapter and parse every WSTG document. */
export function parseWstgDocuments(): WstgDocument[] {
  const docs: WstgDocument[] = [];
  if (!fs.existsSync(WSTG_TESTING_DIR)) return docs;

  const stack: string[] = [WSTG_TESTING_DIR];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!ent.name.endsWith(".md")) continue;
      let content: string;
      try {
        content = fs.readFileSync(full, "utf8");
      } catch {
        continue;
      }
      const doc = parseWstgMarkdown(content, path.relative(WSTG_TESTING_DIR, full));
      if (doc) docs.push(doc);
    }
  }
  return docs;
}

/** Union of curated + inline CWEs for a document. */
export function cwesForDocument(doc: WstgDocument): string[] {
  const curated = WSTG_TO_CWES[doc.id] ?? [];
  return Array.from(new Set([...curated, ...doc.inlineCwes]));
}

export class WstgAdapter implements FpSourceAdapter {
  id = "wstg";
  name = "OWASP WSTG (knowledge + checklist)";

  async fetch(): Promise<void> {
    ensureGitRepo(WSTG_REPO, WSTG_DIR);
  }

  /** WSTG provides testing guidance, not regex FP patterns. */
  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    return [];
  }

  /**
   * Merge a short "how to test" line per WSTG test into each mapped CWE's
   * detection guidance. The orchestrator unions these into
   * `CweKnowledge.detectionGuidance.methods`.
   */
  async parseCweKnowledge(): Promise<NormalizedCweKnowledge[]> {
    const docs = parseWstgDocuments();
    const byCwe = new Map<string, string[]>();
    for (const doc of docs) {
      for (const cwe of cwesForDocument(doc)) {
        const line = `[${doc.id}] ${doc.title}${doc.summary ? ` — ${doc.summary}` : ""}`;
        byCwe.set(cwe, [...(byCwe.get(cwe) ?? []), line]);
      }
    }

    const results: NormalizedCweKnowledge[] = [];
    for (const [cweId, methods] of byCwe) {
      results.push({
        cweId,
        name: CWE_NAMES[cweId] ?? cweId,
        category: undefined,
        description: undefined,
        extendedDescription: undefined,
        commonFalsePositives: [],
        doNotFlag: [],
        detectionMethods: methods,
        mitigations: [],
        owaspTop10: undefined,
        mitreTop25Rank: undefined,
        source: "wstg",
      });
    }
    return results;
  }
}

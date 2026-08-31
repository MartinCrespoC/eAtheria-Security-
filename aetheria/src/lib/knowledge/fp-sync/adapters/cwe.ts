/**
 * FP Knowledge System — MITRE CWE adapter.
 *
 * Downloads the official CWE catalog (`cwec_latest.xml.zip`), unzips it and
 * parses the XML into enriched `CweKnowledge` rows: description, detection
 * methods, mitigations, OWASP Top-10 mapping and (when present) the MITRE
 * Top-25 rank. This is KNOWLEDGE (fed to the detector context + AI prompt),
 * NOT regex patterns — so `parsePatterns()` returns nothing.
 *
 * The XML is large; we parse it once with fast-xml-parser and keep only concise
 * fields. `commonFalsePositives` is left empty here (the curated scan-knowledge
 * base owns those); we instead surface `doNotFlag` guidance derived from the
 * catalog's mitigations so the AI prompt can avoid over-flagging.
 */
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { XMLParser } from "fast-xml-parser";
import { VENDOR_ROOT, ensureHttpFile } from "../orchestrator";
import type { FpSourceAdapter, NormalizedCweKnowledge, NormalizedFpPattern } from "../types";

const CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
const CWE_DIR = path.join(VENDOR_ROOT, "cwe");
const ZIP_PATH = path.join(CWE_DIR, "cwec_latest.xml.zip");

/** A parsed XML element: a plain object with arbitrary children. */
type XmlNode = Record<string, unknown>;

/** Coerce a fast-xml-parser node that may be a single object or an array. */
function toArray(value: unknown): XmlNode[] {
  if (value == null) return [];
  return Array.isArray(value) ? (value as XmlNode[]) : [value as XmlNode];
}

/** Narrow an unknown node to a single object element (or undefined). */
function node(value: unknown): XmlNode | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as XmlNode)
    : undefined;
}

/** Extract text from a node that may be a string or `{ '#text': ... }`. */
function text(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number") return String(value);
  if (typeof value === "object" && "#text" in (value as Record<string, unknown>)) {
    return String((value as Record<string, unknown>)["#text"]).trim();
  }
  return "";
}

export class CweAdapter implements FpSourceAdapter {
  id = "cwe";
  name = "MITRE CWE (knowledge)";
  private xmlPath = "";

  async fetch(): Promise<void> {
    await ensureHttpFile(CWE_XML_ZIP_URL, ZIP_PATH);
    // Unzip (overwrite) into the cwe dir. Non-fatal errors bubble to orchestrator.
    execFileSync("unzip", ["-o", ZIP_PATH, "-d", CWE_DIR], { stdio: "pipe", timeout: 120000 });
    const xmlFile = fs
      .readdirSync(CWE_DIR)
      .find((f) => f.endsWith(".xml") && f.toLowerCase().includes("cwec"));
    if (!xmlFile) throw new Error("No cwec*.xml found after unzip");
    this.xmlPath = path.join(CWE_DIR, xmlFile);
  }

  async parsePatterns(): Promise<NormalizedFpPattern[]> {
    // CWE provides knowledge, not regex FP patterns.
    return [];
  }

  async parseCweKnowledge(): Promise<NormalizedCweKnowledge[]> {
    if (!this.xmlPath) throw new Error("fetch() must run before parseCweKnowledge()");
    const xml = fs.readFileSync(this.xmlPath, "utf8");

    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
      // Keep these as arrays even when a single child is present.
      isArray: (name) =>
        ["Weakness", "Detection_Method", "Mitigation", "Consequence", "Taxonomy_Mapping", "Has_Member"].includes(
          name
        ),
    });
    const doc: XmlNode = parser.parse(xml);
    const catalog = node(doc.Weakness_Catalog);
    if (!catalog) throw new Error("Unexpected CWE XML shape: no Weakness_Catalog root");

    // Build MITRE Top-25 rank map from view 1003 (order of Has_Member).
    const top25Rank = new Map<string, number>();
    for (const view of toArray(node(catalog.Views)?.View)) {
      const viewId = String(view?.["@_ID"] ?? "");
      if (viewId !== "1003") continue;
      const members = toArray(node(view.Members)?.Has_Member);
      members.forEach((m, idx) => {
        const cweId = String(m?.["@_CWE_ID"] ?? "");
        if (cweId && !top25Rank.has(cweId)) top25Rank.set(cweId, idx + 1);
      });
    }

    const results: NormalizedCweKnowledge[] = [];
    for (const w of toArray(node(catalog.Weaknesses)?.Weakness)) {
      const id = String(w?.["@_ID"] ?? "");
      const name = String(w?.["@_Name"] ?? "").trim();
      const abstraction = String(w?.["@_Abstraction"] ?? "");
      if (!id || !name) continue;
      // Skip deprecated entries.
      if (String(w?.["@_Status"] ?? "").toLowerCase() === "deprecated") continue;
      // Focus on actionable abstractions to keep the table signal-dense.
      if (abstraction && !["Base", "Class", "Variant"].includes(abstraction)) continue;

      const cweId = `CWE-${id}`;
      const description = text(w?.Description);
      const extendedDescription = text(w?.Extended_Description);

      const detectionMethods = toArray(node(w.Detection_Methods)?.Detection_Method)
        .map((dm) => {
          const method = text(dm?.Method);
          const eff = text(dm?.Effectiveness);
          const desc = text(dm?.Description);
          return [method, eff ? `(${eff})` : "", desc].filter(Boolean).join(" ").trim();
        })
        .filter(Boolean);

      const mitigations = toArray(node(w.Potential_Mitigations)?.Mitigation)
        .map((m) => text(m?.Description))
        .filter((d) => d.length > 0)
        // Keep mitigations concise for prompt injection.
        .map((d) => (d.length > 280 ? `${d.slice(0, 277)}...` : d));

      // OWASP Top 10 2021 mapping (prefer the 2021 taxonomy).
      let owaspTop10: string | undefined;
      for (const tm of toArray(node(w.Taxonomy_Mappings)?.Taxonomy_Mapping)) {
        const tax = String(tm?.["@_Taxonomy_Name"] ?? "");
        if (/OWASP Top 10/i.test(tax) && /2021/.test(tax)) {
          owaspTop10 = text(tm?.Entry_ID) || undefined;
          break;
        }
      }

      // Derive "DO NOT FLAG" guidance from high-effectiveness automated analysis
      // being available + mitigations that describe safe patterns.
      const doNotFlag: string[] = [];
      const hasAutomatedDetection = toArray(node(w.Detection_Methods)?.Detection_Method).some((dm) =>
        /automated static analysis|automated dynamic analysis/i.test(text(dm?.Method))
      );
      if (hasAutomatedDetection && mitigations.length) {
        doNotFlag.push(
          `${cweId} (${name}): do not flag when the code already applies a documented mitigation.`
        );
      }

      results.push({
        cweId,
        name,
        category: abstraction || undefined,
        description: description || undefined,
        extendedDescription: extendedDescription || undefined,
        commonFalsePositives: [],
        doNotFlag,
        detectionMethods,
        mitigations,
        owaspTop10,
        mitreTop25Rank: top25Rank.get(cweId),
        source: "cwe",
      });
    }

    return results;
  }
}

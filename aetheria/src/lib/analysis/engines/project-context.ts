/**
 * Project-context engine — cross-file analysis over a full project tree.
 *
 * Single-file analysis seeds every exported-function parameter as attacker
 * input (the library trust-boundary assumption). That is the right default
 * when callers are unknown, but it produces semantic twins: a patch that adds
 * validation AT THE CALL SITES (often in another file) leaves the exported
 * function's body — and therefore the single-file findings — unchanged.
 *
 * With the full project tree available, this module re-evaluates taint
 * findings whose source is an exported-function parameter: it resolves the
 * module graph, finds every in-project call site of the exporting function,
 * and checks the actual argument expressions. If the function has at least
 * one in-project call site and EVERY call site passes data that is provably
 * clean (literal/constant, sanitized, or guarded upstream), the flow is clean
 * and the finding is suppressed with an auditable reason.
 *
 * Conservative by construction: unknown argument provenance counts as dirty,
 * zero call sites means no suppression (external consumers may exist), and
 * only findings sourced from exported parameters are eligible — everything
 * else keeps the single-file verdict.
 */
import {
  calleeReturnsTaint,
  indexLocalFunctions,
} from "./taint-engine";

export interface ProjectVerdict {
  suppress: boolean;
  reason?: string;
  /** Debug: why the verdict was not suppressive. */
  detail?: "not-taint" | "not-param-source" | "no-taint-path" | "parse-fail" | "file-not-found" | "no-owner" | "no-callers" | "dirty-callsites";
}

export interface ProjectVerdictInput {
  detectionMethod: string;
  source?: string;
  taintPath?: string[];
  /** Repo-relative path of the analyzed file. */
  filePath: string;
  fileContent: string;
  projectFiles: Map<string, string>;
  /** DB sanitizer patterns for the language (substring matching). */
  sanitizers: string[];
  /** DB source patterns for the language (substring matching). */
  sources: string[];
}

// ─────────────────────────────── text utilities ───────────────────────────────

/** Blank string/template literals and comments, preserving structure. */
function maskNonCode(line: string): string {
  let out = "";
  let i = 0;
  let inLine = false;
  let inBlock = false;
  let quote: string | null = null;
  while (i < line.length) {
    const ch = line[i];
    const next = line[i + 1];
    if (inLine) break;
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i += 2;
        out += "  ";
        continue;
      }
      out += " ";
      i++;
      continue;
    }
    if (quote) {
      if (ch === "\\") {
        out += "  ";
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      out += " ";
      i++;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      break;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      out += "  ";
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      out += ch;
      i++;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Split a JS argument list on top-level commas (depth-aware). */
function splitTopLevelArgs(raw: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      cur += ch;
      if (ch === "\\") cur += raw[++i] ?? "";
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      args.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) args.push(cur);
  return args;
}

// ─────────────────────────────── module graph ────────────────────────────────

const JS_EXTS = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"];

/** Resolve a relative import path against the project file set, or null. */
function resolveModule(fromFile: string, spec: string, files: Map<string, string>): string | null {
  if (!spec.startsWith("./") && !spec.startsWith("../")) return null;
  const fromDir = fromFile.split("/").slice(0, -1);
  const parts = spec.split("/");
  const resolved: string[] = [...fromDir];
  for (const p of parts) {
    if (p === "." || p === "") continue;
    else if (p === "..") resolved.pop();
    else resolved.push(p);
  }
  const base = resolved.join("/");
  const candidates = [base, ...JS_EXTS.map((e) => base + e), ...JS_EXTS.map((e) => `${base}/index${e}`)];
  for (const c of candidates) {
    if (files.has(c)) return c;
  }
  return null;
}

interface RequireBinding {
  /** Local names bound to the module: namespace, destructured, or default. */
  namespaces: string[];
  destructured: Map<string, string>; // local name → exported name
  /** true when the module itself is called as a function. */
  moduleAsFunction: boolean;
}

/** Extract require/import bindings pointing at `targetPath` from one file. */
function bindingsForTarget(
  filePath: string,
  content: string,
  targetPath: string,
  files: Map<string, string>,
): RequireBinding | null {
  const out: RequireBinding = { namespaces: [], destructured: new Map(), moduleAsFunction: false };
  const lines = content.split("\n");
  let found = false;
  for (const raw of lines) {
    // NOTE: raw line — the module specifier IS a string literal, which
    // maskNonCode would blank out.
    const req = raw.match(/\brequire\s*\(\s*(['"`])([^'"`]+)\1\s*\)/);
    const imp = raw.match(/\bimport\s+(?:([^'"]+?)\s+from\s+)?(['"`])([^'"`]+)\2/);
    const spec = req?.[2] ?? imp?.[3];
    if (!spec) continue;
    const resolved = resolveModule(filePath, spec, files);
    if (resolved !== targetPath) continue;
    found = true;
    if (req) {
      // const x = require('./a')  /  const {a, b: c} = require('./a')
      const prefix = raw.slice(0, raw.indexOf("require"));
      const dest = prefix.match(/\{([^}]+)\}/);
      if (dest) {
        for (const part of dest[1].split(",")) {
          const m = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/);
          if (m) out.destructured.set(m[2] ?? m[1], m[1]);
        }
      } else {
        const ns = prefix.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$/);
        if (ns) {
          out.namespaces.push(ns[1]);
          out.moduleAsFunction = true;
        }
      }
    } else if (imp && imp[1]) {
      const clause = imp[1].trim();
      const dest = clause.match(/\{([^}]+)\}/);
      if (dest) {
        for (const part of dest[1].split(",")) {
          const m = part.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
          if (m) out.destructured.set(m[2] ?? m[1], m[1]);
        }
      }
      const star = clause.match(/\*\s+as\s+([A-Za-z_$][\w$]*)/);
      if (star) out.namespaces.push(star[1]);
      const def = clause.match(/^([A-Za-z_$][\w$]*)\s*(?:,|$)/);
      if (def && !clause.startsWith("{") && !clause.startsWith("*")) {
        out.namespaces.push(def[1]);
        out.moduleAsFunction = true;
      }
    }
  }
  return found ? out : null;
}

// ──────────────────────── exported-function identification ───────────────────

interface ExportedFnRef {
  /** Exported name to look up at call sites; "<module>" = module-as-function. */
  exportName: string;
  /** 0-based position of the tainted parameter in the signature. */
  paramIndex: number;
}

/** Parse a parameter list and return the index of `paramName`, or -1. */
function paramIndexOf(paramsRaw: string, paramName: string): number {
  const parts = splitTopLevelArgs(paramsRaw);
  for (let i = 0; i < parts.length; i++) {
    const m = parts[i].trim().match(/^([A-Za-z_$][\w$]*)/);
    if (m && m[1] === paramName) return i;
  }
  return -1;
}

/**
 * Identify which exported function owns the seeded parameter at `line`
 * (1-based) in the affected file. Returns null for shapes where call-site
 * resolution is unreliable (prototype methods, class methods).
 */
function findExportedOwner(
  lines: string[],
  line: number,
  paramName: string,
): ExportedFnRef | null {
  const masked = maskNonCode(lines[line - 1] ?? "");
  // exports.foo = function (…) / module.exports.foo = (…) =>
  const member = masked.match(
    /(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)/,
  );
  if (member) {
    const params = member[2] ?? member[3] ?? member[4] ?? "";
    const idx = paramIndexOf(params, paramName);
    if (idx >= 0) return { exportName: member[1], paramIndex: idx };
    return null;
  }
  // module.exports = function (…) — the module itself is the function.
  const moduleFn = masked.match(/module\s*\.\s*exports\s*=\s*(?:async\s+)?function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/);
  if (moduleFn) {
    const idx = paramIndexOf(moduleFn[1], paramName);
    return idx >= 0 ? { exportName: "<module>", paramIndex: idx } : null;
  }
  // Object-literal member: `foo: function (…)` / `foo(…) {` / `foo: (…) =>`
  const objMember = masked.match(
    /\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)/,
  );
  if (objMember) {
    const params = objMember[2] ?? objMember[3] ?? objMember[4] ?? "";
    const idx = paramIndexOf(params, paramName);
    if (idx >= 0) return { exportName: objMember[1], paramIndex: idx };
    return null;
  }
  const shorthand = masked.match(/^\s*(?:async\s+)?(?!function\b)([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{?\s*$/);
  if (shorthand) {
    const idx = paramIndexOf(shorthand[2], paramName);
    if (idx >= 0) return { exportName: shorthand[1], paramIndex: idx };
    return null;
  }
  // Prototype/class methods: skip (call-site resolution unreliable).
  if (/\.\s*prototype\s*\./.test(masked)) return null;

  // Named declaration exported elsewhere: `function foo(…)` /
  // `const foo = (…) => …` with `module.exports = foo` / `export … foo`.
  const named =
    masked.match(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)/) ??
    masked.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/) ??
    masked.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/);
  if (named) {
    const params = named[2] ?? "";
    const isExported = lines.some((l) => {
      const m2 = maskNonCode(l);
      return (
        new RegExp(`module\\s*\\.\\s*exports\\s*=\\s*${escapeRegex(named[1])}\\s*;?\\s*$`).test(m2) ||
        new RegExp(`\\bexport\\s+default\\s+${escapeRegex(named[1])}\\s*;?\\s*$`).test(m2) ||
        new RegExp(`\\bexports\\s*\\.\\s*${escapeRegex(named[1])}\\s*=`).test(m2) ||
        new RegExp(`\\bexport\\s*\\{[^}]*\\b${escapeRegex(named[1])}\\b`).test(m2)
      );
    });
    if (isExported) {
      const idx = paramIndexOf(params, paramName);
      if (idx >= 0) return { exportName: named[1], paramIndex: idx };
    }
    return null;
  }
  return null;
}

// ───────────────────────────── argument verdicts ─────────────────────────────

type ArgVerdict = "clean" | "dirty";

/** Literal/constant expression (no identifiers). */
function isConstantExpr(expr: string): boolean {
  const t = expr.trim();
  if (/^(['"`])[\s\S]*\1$/.test(t) && !/\$\{/.test(t)) return true;
  if (/^-?\d+(?:\.\d+)?$/.test(t)) return true;
  if (/^(?:true|false|null|undefined|NaN|Infinity)$/.test(t)) return true;
  return false;
}

/**
 * Verdict for one call-site argument expression within the caller file.
 * Anything whose provenance cannot be proven clean is dirty.
 */
function argVerdict(
  arg: string,
  callerLines: string[],
  callLineIdx: number,
  sanitizers: string[],
  sources: string[],
  fnIndex: Map<string, ReturnType<typeof indexLocalFunctions> extends Map<string, infer V> ? V : never>,
  depth = 0,
): ArgVerdict {
  const trimmed = arg.trim();
  if (!trimmed) return "dirty";
  if (isConstantExpr(trimmed)) return "clean";
  // Sanitizer applied to the argument wins over a nested source token:
  // `sanitize(process.argv[2])` is exactly the call-site patch shape.
  if (sanitizers.some((s) => trimmed.includes(s))) return "clean";
  // Explicit taint source in the argument → dirty.
  if (sources.some((s) => trimmed.includes(s))) return "dirty";

  // Call expression: the callee provably discards taint → clean.
  const call = trimmed.match(/^([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)$/);
  if (call) {
    const fn = fnIndex.get(call[1]);
    if (fn && depth < 2) {
      const bound = new Set<string>();
      splitTopLevelArgs(call[2]).forEach((a, idx) => {
        if (fn.params[idx] && a.trim()) bound.add(fn.params[idx]);
      });
      if (bound.size > 0 && !calleeReturnsTaint(fn, bound, callerLines, sanitizers, fnIndex, depth + 1)) {
        return "clean";
      }
    }
    // Unknown callee that receives a possibly-tainted expression → dirty.
    return "dirty";
  }

  // Bare identifier: trace its nearest preceding assignment in the caller.
  const ident = trimmed.match(/^([A-Za-z_$][\w$]*)$/);
  if (ident && depth < 2) {
    const name = ident[1];
    if (/^(?:undefined|null|true|false)$/.test(name)) return "clean";
    for (let k = callLineIdx - 1; k >= 0 && k > callLineIdx - 30; k--) {
      const masked = maskNonCode(callerLines[k]);
      const assign = masked.match(new RegExp(`\\b(?:const|let|var)?\\s*${escapeRegex(name)}\\s*=\\s*(.+?);?\\s*$`));
      if (assign) {
        return argVerdict(assign[1], callerLines, k, sanitizers, sources, fnIndex, depth + 1);
      }
    }
    // Function parameter / unresolved → dirty.
    return "dirty";
  }

  // Member access on a constant object or a known-safe expression: resolve the base.
  const member = trimmed.match(/^([A-Za-z_$][\w$]*)(?:\s*\.\s*[\w$]+)+$/);
  if (member && depth < 2) {
    return argVerdict(member[1], callerLines, callLineIdx, sanitizers, sources, fnIndex, depth + 1);
  }

  // Guarded upstream: `if (!check(arg)) return/throw` in the lines above.
  if (ident) {
    const name = escapeRegex(ident[1]);
    for (let k = callLineIdx - 1; k >= 0 && k > callLineIdx - 10; k--) {
      const masked = maskNonCode(callerLines[k]);
      const guard = masked.match(
        new RegExp(`\\bif\\s*\\(\\s*!?\\s*[A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*\\s*\\(\\s*${name}\\s*\\)`),
      );
      if (guard) {
        const tail = callerLines.slice(k, Math.min(callerLines.length, k + 6)).join("\n");
        if (/\b(?:return|throw|continue|break)\b/.test(tail)) return "clean";
      }
    }
  }

  return "dirty";
}

// ─────────────────────────────── main entry point ────────────────────────────

/**
 * Re-evaluate a kept finding with full-project context. Returns
 * `{suppress: true}` only when the finding's tainted exported parameter is
 * provably reached with clean data at every in-project call site.
 */
export function evaluateFindingWithProject(input: ProjectVerdictInput): ProjectVerdict {
  const { detectionMethod, source, taintPath, filePath, fileContent, projectFiles, sanitizers, sources } = input;
  if (detectionMethod !== "TAINT") return { suppress: false, detail: "not-taint" };
  if (source !== "exported-function-parameter") return { suppress: false, detail: "not-param-source" };
  if (!taintPath || taintPath.length === 0) return { suppress: false, detail: "no-taint-path" };

  const m = taintPath[0].match(/^exported function parameter ([A-Za-z_$][\w$]*) \(line (\d+)\)$/);
  if (!m) return { suppress: false, detail: "parse-fail" };
  const paramName = m[1];
  const seedLine = parseInt(m[2], 10);

  // Locate the affected file inside the project tree.
  const normalizedPath = filePath.replace(/\\/g, "/").replace(/^\/+/, "");
  const projectPath = projectFiles.has(normalizedPath)
    ? normalizedPath
    : [...projectFiles.keys()].find((k) => k === normalizedPath || k.endsWith("/" + normalizedPath));
  if (!projectPath) return { suppress: false, detail: "file-not-found" };
  const content = projectFiles.get(projectPath) ?? fileContent;
  const lines = content.split("\n");

  const owner = findExportedOwner(lines, seedLine, paramName);
  if (!owner) return { suppress: false, detail: "no-owner" };

  // Scan every project file for bindings to the affected module.
  let callSites = 0;
  let allClean = true;
  let evidence = "";
  for (const [callerPath, callerContent] of projectFiles) {
    if (!JS_EXTS.some((e) => callerPath.endsWith(e))) continue;
    const binding = bindingsForTarget(callerPath, callerContent, projectPath, projectFiles);
    if (!binding) continue;
    const callerLines = callerContent.split("\n");
    const fnIndex = indexLocalFunctions(callerLines);

    // Build the set of call-site regexes for this binding.
    const callPatterns: RegExp[] = [];
    if (owner.exportName === "<module>") {
      if (binding.moduleAsFunction) {
        for (const ns of binding.namespaces) callPatterns.push(new RegExp(`\\b${escapeRegex(ns)}\\s*\\(`));
      }
    } else {
      for (const ns of binding.namespaces) {
        callPatterns.push(new RegExp(`\\b${escapeRegex(ns)}\\s*\\.\\s*${escapeRegex(owner.exportName)}\\s*\\(`));
      }
      for (const [local, exported] of binding.destructured) {
        if (exported === owner.exportName) {
          callPatterns.push(new RegExp(`\\b${escapeRegex(local)}\\s*\\(`));
        }
      }
    }

    for (const re of callPatterns) {
      for (let i = 0; i < callerLines.length; i++) {
        const masked = maskNonCode(callerLines[i]);
        // Skip the binding line itself (`const foo = require(…)`).
        if (/require\s*\(|\bimport\s/.test(masked)) continue;
        const cm = masked.match(re);
        if (!cm) continue;
        // Join continuation lines until parens balance.
        let joined = callerLines[i];
        let opens = (joined.match(/\(/g) ?? []).length;
        let closes = (joined.match(/\)/g) ?? []).length;
        for (let k = i + 1; k < Math.min(callerLines.length, i + 8) && opens > closes; k++) {
          joined += "\n" + callerLines[k];
          opens += (callerLines[k].match(/\(/g) ?? []).length;
          closes += (callerLines[k].match(/\)/g) ?? []).length;
        }
        const openIdx = joined.indexOf(cm[0]) + cm[0].length;
        const closeIdx = joined.lastIndexOf(")");
        const argsRaw = closeIdx > openIdx ? joined.slice(openIdx, closeIdx) : "";
        const args = splitTopLevelArgs(argsRaw);
        const arg = args[owner.paramIndex];
        callSites++;
        const verdict =
          arg === undefined
            ? ("dirty" as ArgVerdict)
            : argVerdict(arg, callerLines, i, sanitizers, sources, fnIndex);
        if (verdict === "dirty") {
          allClean = false;
        } else if (!evidence) {
          evidence = `${callerPath}:${i + 1}`;
        }
      }
    }
  }

  if (callSites === 0 || !allClean) {
    return { suppress: false, detail: callSites === 0 ? "no-callers" : "dirty-callsites" };
  }
  return {
    suppress: true,
    reason: `Project context: all ${callSites} in-project call sites of the exported function pass sanitized/constant input (e.g. ${evidence}) — validation at the call site is the patch.`,
  };
}

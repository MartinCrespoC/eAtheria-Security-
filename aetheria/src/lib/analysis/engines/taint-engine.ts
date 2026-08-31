/**
 * Deterministic Taint Tracking Engine
 * Traces data flow from Sources (user input) through variable assignments
 * to Sinks (dangerous operations), checking for Sanitizers along the path.
 *
 * All rules are loaded from the database (TaintSource, TaintSink, TaintSanitizer models).
 * This is NOT AI-based — it's a deterministic source→sink analyzer.
 */

export interface TaintFinding {
  cwe: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  owasp2021: string;
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  confidence: number;
  source: string;
  sink: string;
  sanitizerFound: boolean;
  taintPath: string[];
  detectionMethod: "TAINT";
}

export interface DbTaintSource {
  language: string;
  pattern: string;
}

export interface DbTaintSink {
  language: string;
  pattern: string;
  cwe: string;
  category: string;
  severity: string;
  owasp2021: string;
}

export interface DbTaintSanitizer {
  language: string;
  pattern: string;
}

export interface TaintRulesBundle {
  sources: DbTaintSource[];
  sinks: DbTaintSink[];
  sanitizers: DbTaintSanitizer[];
}

interface TaintedVar {
  name: string;
  sourceLine: number;
  source: string;
  path: string[];
}

/**
 * Element model for list-like collections built via `.add(...)`. Each entry is
 * the TaintedVar the element was added from, or null when the element is a
 * provably-untainted value (literal or clean variable). This lets
 * `x = list.get(N)` resolve taint by INDEX instead of treating the whole
 * collection as tainted — the OWASP Benchmark safe cases rely on this:
 *   valuesList.add("safe"); valuesList.add(param); valuesList.add("moresafe");
 *   valuesList.remove(0); bar = valuesList.get(1); // "moresafe", NOT param
 */
type ListElement = TaintedVar | null;

/**
 * Tracks dead (unreachable) code regions caused by provably-constant control-flow
 * conditions. The OWASP Benchmark FALSE cases heavily use:
 *   - `if (always_true) bar = "safe"; else bar = param;`  (else is dead)
 *   - `switch (constTarget) { case 'A': bar = param; case 'B': bar = "safe"; }`
 * Without dead-branch tracking, the engine taints `bar` from the unreachable branch.
 */
interface DeadBranchState {
  /** Currently inside a dead (unreachable) multi-line code region. */
  dead: boolean;
  kind: "none" | "if-else" | "switch";
  /** For switch: the resolved constant value of the switch target. */
  switchValue: string | null;
  /** For switch: whether the current case label matches. */
  caseLive: boolean;
  /** Brace depth tracking for multi-line else blocks. */
  braceDepth: number;
}

export function runTaintAnalysis(
  fileContent: string,
  filePath: string,
  language: string,
  rules: TaintRulesBundle,
): TaintFinding[] {
  const lines = fileContent.split("\n");
  const { sources, sinks, sanitizers } = filterRules(language, rules);
  if (sources.length === 0 && sinks.length === 0) return [];

  // NOTE: a file-wide "archive sources are validated somewhere" suppression was
  // considered and rejected — extraction libraries keep per-entry guards that
  // do NOT cover every flow (node-tar's [CHECKPATH] exists in BOTH the
  // vulnerable and patched revisions of CVE-2018-20834; the actual fix was
  // symlink validation elsewhere). Per-function guards remain in force below.

  const {
    vars: taintedVars,
    collections: taintedCollections,
    inertElements,
    props: taintedProps,
  } = computeTaintPropagation(lines, language, sources, sanitizers);
  const findings: TaintFinding[] = [];

  // Local function index for local-sanitizer neutralization in the sink loop
  // (`exec(sanitize(x))` where sanitize provably discards its input).
  const fnIndexTop =
    language === "javascript" || language === "typescript"
      ? indexLocalFunctions(lines)
      : null;

  // Sink regexes are compiled ONCE per run (not per line) — a meaningful speedup
  // when scanning thousands of benchmark cases.
  const compiledSinks = sinks.map((sink) => ({
    sink,
    regex: toRegex(sink.pattern),
  }));

  // Require-alias sinks (JS/TS): real-world code calls process-spawning APIs
  // through local aliases (`const proc = require('child_process').exec; proc(cmd)`
  // — CVE-2018-16461) that DB regexes cannot name. Resolve the aliases here and
  // treat calls through them as the corresponding command-execution sink.
  if (language === "javascript" || language === "typescript") {
    const CMD_METHODS =
      "(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)";
    const aliasSink = (pattern: string): void => {
      compiledSinks.push({
        sink: {
          language,
          pattern,
          cwe: "CWE-78",
          category: "OS Command Injection",
          severity: "CRITICAL",
          owasp2021: "A03:2021",
        },
        regex: toRegex(pattern),
      });
    };
    for (const rawLine of lines) {
      // NOTE: use the RAW line — maskNonCode blanks string literals, and the
      // module name ('child_process') IS the signal here.
      const masked = rawLine;
      const methodAlias = masked.match(
        new RegExp(
          `\\b([A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*['\"]child_process['\"]\\s*\\)\\s*\\.\\s*${CMD_METHODS}\\b`,
        ),
      );
      if (methodAlias) aliasSink(`\\b${escapeRegex(methodAlias[1])}\\s*\\(`);
      const moduleAlias = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)\s*;?\s*$/,
      );
      if (moduleAlias)
        aliasSink(
          `\\b${escapeRegex(moduleAlias[1])}\\s*\\.\\s*${CMD_METHODS}\\s*\\(`,
        );
      const shellAlias = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]shelljs['"]\s*\)/,
      );
      if (shellAlias)
        aliasSink(`\\b${escapeRegex(shellAlias[1])}\\s*\\.\\s*exec\\s*\\(`);
      // execa: `sh = require('execa').shell` / `const run = require('execa')`
      // (CVE-2019-5414). The module itself is callable; shell/shellSync/sync/
      // command members execute commands too.
      const execaMember = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]execa['"]\s*\)\s*\.\s*(?:shell|shellSync|sync|exec|command)\b/,
      );
      if (execaMember) aliasSink(`\\b${escapeRegex(execaMember[1])}\\s*\\(`);
      const execaModule = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]execa['"]\s*\)\s*;?\s*$/,
      );
      if (execaModule)
        aliasSink(
          `\\b${escapeRegex(execaModule[1])}\\s*(?:\\.\\s*(?:shell|shellSync|sync|exec|command))?\\s*\\(`,
        );
      // promisify-wrapped exec: `const execPromise = promisify(exec)` — the
      // wrapper preserves the command-execution semantics (CVE-2019-10776).
      const promisified = masked.match(
        new RegExp(
          `\\b([A-Za-z_$][\\w$]*)\\s*=\\s*(?:util\\s*\\.\\s*)?promisify\\s*\\(\\s*(?:child_process\\s*\\.\\s*)?${CMD_METHODS}\\s*\\)`,
        ),
      );
      if (promisified) aliasSink(`\\b${escapeRegex(promisified[1])}\\s*\\(`);
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip comments
    if (
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("*") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("--")
    ) {
      continue;
    }

    // Step 3: Detect sinks — check if tainted data reaches a dangerous call
    for (const { sink, regex } of compiledSinks) {
      if (regex.test(line)) {
        // Declaration lines are not sink CALLS: `export function open(path, ref)`
        // declares parameters (and the seeded taint is exactly those params), so
        // a sink regex matching the declaration (`open(`) must not fire on it.
        // The declaration shape requires a params list free of call artifacts
        // (quotes, `+`, nested calls, callbacks) — a CALL like
        // `exec(cmd + pid, function (err, out) {` keeps its sink semantics.
        if (/\bfunction\s+[A-Za-z_$][\w$]*\s*\(/.test(line)) continue;
        if (/\{\s*$/.test(line)) {
          const decl = line.match(
            /^\s*(?:export\s+(?:default\s+)?)?(?:public\s+|private\s+|protected\s+|static\s+|async\s+|get\s+|set\s+)*[A-Za-z_$][\w$]*\s*\(([^()]*)\)\s*(?::\s*[\w$[\]<>| ]+)?\s*\{\s*$/,
          );
          if (decl && !/[+/'"`]|\bfunction\b/.test(decl[1])) continue;
        }
        // Path-composition sinks (path.join/resolve, CWE-22) — generic gates
        // (composition / tainted-tail / forward-confinement), shared with the
        // inter-procedural pass. See isConfinedPathJoin.
        if (isConfinedPathJoin(sink, lines, i, [...taintedVars.keys()]))
          continue;
        // Inert-document suppression: HTML written to an element of an INERT
        // document (`document.implementation.createHTMLDocument()`) cannot
        // execute — this is the standard sanitizer-library pattern (DOMPurify,
        // html-janitor's fix for CVE-2017-0931). Only applies to assignment
        // sinks (`el.innerHTML = …`) whose receiver is provably inert.
        if (inertElements.size > 0) {
          const recv = maskNonCode(line).match(
            /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:innerHTML|outerHTML)\s*=/,
          );
          if (recv && inertElements.has(recv[1])) continue;
        }
        // Multiline support: (a) the tainted argument sits on the next line(s)
        // of an UNCLOSed call (`connection.prepareStatement(\n  sql)`), and (b)
        // the statement is operator-CONTINUED (`el.innerHTML = '<svg…' +\n
        // location.href + …` — CVE-2020-15138's multi-line concat).
        let taintedInSink = findTaintedInSinkCall(
          line,
          regex,
          taintedVars,
          lineNum,
        );
        const parenOpen = hasUnclosedParen(line);
        // NOTE: no `,` here — a line ending with a comma and balanced parens is
        // a multi-DECLARATION (`var params = f(…), key = g(…)`), not a
        // continued expression; looking ahead crosses statement boundaries
        // (CVE-2020-7662 post FP).
        const opContinued = /[+&|?:`]\s*$/.test(line.trimEnd()) && !/[;{}]\s*$/.test(line.trimEnd());
        const continuation: string[] = [];
        if (!taintedInSink && (parenOpen || opContinued)) {
          const maxAhead = parenOpen ? 2 : 10;
          for (let k = 1; k <= maxAhead && i + k < lines.length; k++) {
            const ahead = lines[i + k];
            continuation.push(ahead);
            taintedInSink = findTaintedInLine(ahead, taintedVars, lineNum + k);
            if (taintedInSink) break;
            if (ahead.includes(";") || (parenOpen && ahead.includes(")"))) break;
          }
        }
        // CWE-78 collection check: if no direct tainted var found, check if a
        // tainted collection (List/Set with tainted .add()) appears on this line.
        if (
          !taintedInSink &&
          sink.cwe === "CWE-78" &&
          taintedCollections.size > 0
        ) {
          taintedInSink = findTaintedInLine(line, taintedCollections, lineNum);
        }
        // Property taint: `this.x` holding attacker data (stored by a
        // constructor/setter from an exported/event/route parameter) reaching
        // the sink — class-based libraries (JS/TS).
        if (!taintedInSink && taintedProps.size > 0) {
          for (const prop of taintedProps) {
            if (
              new RegExp(`\\bthis\\s*\\.\\s*${escapeRegex(prop)}\\b`).test(line)
            ) {
              taintedInSink = {
                name: `this.${prop}`,
                sourceLine: lineNum,
                source: "tainted-property",
                path: [`tainted property this.${prop}`],
              };
              break;
            }
          }
        }

        if (taintedInSink) {
          // Local-sanitizer neutralization: the tainted var reaches the sink
          // WRAPPED in a local call whose return provably discards its input —
          // the patched-code idiom `exec(sanitize(x))`. The sanitizer helper is
          // local and unknown to the DB; a provably clean return neutralizes.
          if (
            fnIndexTop &&
            fnIndexTop.size > 0 &&
            !taintedInSink.name.startsWith("this.")
          ) {
            const wrapRe = new RegExp(
              `([A-Za-z_$][\\w$]*)\\s*\\([^()]*${identPat(taintedInSink.name)}[^()]*\\)`,
            );
            const wm = line.match(wrapRe);
            if (wm) {
              const wrapFn = fnIndexTop.get(wm[1]);
              if (
                wrapFn &&
                wrapFn.params.length > 0 &&
                !calleeReturnsTaint(
                  wrapFn,
                  new Set([wrapFn.params[0]]),
                  lines,
                  sanitizers,
                )
              ) {
                continue; // neutralized — next sink
              }
            }
          }
          const sanitizerOnLine = sanitizers.some((s) => line.includes(s));
          const sanitizerInPath = taintedInSink.path.some((p) =>
            sanitizers.some((s) => p.includes(s)),
          );

          // Array-form process spawn is shell-free: `spawn(cmd, argsArray)` /
          // `execFile(cmd, argsArray)` do not invoke a shell (unless shell:true),
          // so shell metacharacters in the arguments are inert (growl's fix for
          // CVE-2017-16042 switched `exec(args.join(' '))` to `spawn(cmd, args)`).
          // Only `exec`-family calls (single command string → shell) are CWE-78.
          if (
            !sanitizerOnLine &&
            !sanitizerInPath &&
            sink.cwe === "CWE-78" &&
            (/spawn|execFile/.test(sink.pattern) ||
              /(?:execFile|execFileSync|spawn|spawnSync)\s*\(/.test(line))
          ) {
            const callMatch = maskNonCode(line).match(
              /(?:spawn|spawnSync|execFile|execFileSync)\s*\((.*)\)/,
            );
            if (callMatch) {
              const argsStr = callMatch[1];
              let depth = 0;
              let topComma = false;
              for (const ch of argsStr) {
                if (ch === "(" || ch === "[") depth++;
                else if (ch === ")" || ch === "]") depth--;
                else if (ch === "," && depth === 0) {
                  topComma = true;
                  break;
                }
              }
              if (topComma && !/shell\s*:\s*true/.test(line)) continue;
            }
          }

          // NoSQL operator injection is neutralized by string coercion:
          // `${x}` / `x.toString()` forces a primitive string, so an injected
          // `{$gt: ''}` object cannot survive (the CVE-2018-3783 /
          // CVE-2019-18818 fixes are exactly this).
          if (sink.cwe === "CWE-89") {
            const v = escapeRegex(taintedInSink.name);
            if (
              new RegExp(`\\$\\{\\s*${v}\\s*\\}`).test(line) ||
              new RegExp(`\\b${v}\\s*\\.\\s*toString\\s*\\(`).test(line)
            )
              continue;
          }

          // ORM parameterized repository calls (TypeORM `findOne({ where: … })`,
          // `find({ where: … })`): values placed in a `where` options object are
          // bound as query parameters — a tainted scalar property value is NOT
          // SQL injection. Real danger remains: NoSQL operator objects
          // (`$`-prefixed keys, e.g. Mongoose object injection CVE-2018-3783)
          // and spreading a whole tainted object into the query. `where:` is the
          // TypeORM signature; Mongoose queries lack it, so those stay flagged.
          if (
            sink.cwe === "CWE-89" &&
            /\b(?:findOne|findOneBy|findBy|findAndCount)\s*\(\s*\{/.test(
              maskNonCode(line),
            )
          ) {
            const callText = [line, ...continuation].join("\n");
            let maskedCall = maskNonCode(callText);
            // Multiline `findOne({\n  where: … })`: the tainted var may resolve
            // on the opening line (LHS quirk), leaving `continuation` empty —
            // peek ahead for the options object when the paren is unclosed.
            if (!/\bwhere\s*:/.test(maskedCall) && hasUnclosedParen(line)) {
              maskedCall = maskNonCode(
                maskedCall + "\n" + lines.slice(i + 1, i + 4).join("\n"),
              );
            }
            if (
              /\bwhere\s*:/.test(maskedCall) &&
              !/[{,]\s*['"]?\$\w/.test(maskedCall) &&
              !new RegExp(`\\.\\.\\.\\s*${escapeRegex(taintedInSink.name)}\\b`).test(maskedCall)
            )
              continue;
          }

          if (!sanitizerOnLine && !sanitizerInPath) {
            // CONFIRMED: source → sink without sanitizer
            const contextStart = Math.max(0, i - 2);
            const contextEnd = Math.min(lines.length - 1, i + 2);
            const codeSnippet = lines
              .slice(contextStart, contextEnd + 1)
              .join("\n");

            findings.push({
              cwe: sink.cwe,
              category: sink.category,
              severity: sink.severity as TaintFinding["severity"],
              owasp2021: sink.owasp2021,
              title: `${sink.category}: ${sink.cwe} in ${filePath.split("/").pop()}`,
              description: buildDescription(
                sink,
                taintedInSink,
                filePath,
                lineNum,
              ),
              filePath,
              lineStart: taintedInSink.sourceLine,
              lineEnd: lineNum,
              codeSnippet,
              confidence: calculateConfidence(taintedInSink, lineNum),
              source: taintedInSink.source,
              sink: sink.pattern,
              sanitizerFound: false,
              taintPath: [
                ...taintedInSink.path,
                `SINK: ${sink.pattern} (line ${lineNum})`,
              ],
              detectionMethod: "TAINT",
            });
          }
        } else {
          // Sink found but no tainted variable detected on this line.
          // Still flag as potential if the sink pattern matches user-controlled patterns
          // (also across operator-continued lines collected above).
          const hasInlineSource =
            sources.some((s) => line.includes(s)) ||
            continuation.some((ahead) => {
              const maskedAhead = maskNonCode(ahead);
              return sources.some((s) => maskedAhead.includes(s));
            });
          if (hasInlineSource) {
            const contextStart = Math.max(0, i - 1);
            const contextEnd = Math.min(lines.length - 1, i + 1);
            const codeSnippet = lines
              .slice(contextStart, contextEnd + 1)
              .join("\n");
            const sanitizerOnLine = sanitizers.some((s) => line.includes(s));

            if (!sanitizerOnLine) {
              findings.push({
                cwe: sink.cwe,
                category: sink.category,
                severity: sink.severity as TaintFinding["severity"],
                owasp2021: sink.owasp2021,
                title: `${sink.category}: ${sink.cwe} in ${filePath.split("/").pop()}`,
                description: `Direct use of user input in ${sink.category.toLowerCase()} sink at line ${lineNum}. Source and sink on same line without sanitization.`,
                filePath,
                lineStart: lineNum,
                lineEnd: lineNum,
                codeSnippet,
                confidence: 85,
                source: "inline",
                sink: sink.pattern,
                sanitizerFound: false,
                taintPath: [`SOURCE+SINK inline (line ${lineNum})`],
                detectionMethod: "TAINT",
              });
            }
          }
        }
      }
    }

    // HTML accumulator XSS (CWE-79): HTML built via string concat / template
    // interpolation with tainted data — `table += `<tr><td>${enc}</td>``,
    // `res.send(`…${name}…`)`, `list.push('<li>', file, …)`. The tag must
    // live INSIDE a string/template literal — excludes JSX, where tags are
    // syntax, not text.
    if (
      (language === "javascript" || language === "typescript") &&
      taintedVars.size > 0 &&
      /['"`][^'"`]*<\/?(?:a|div|span|td|th|tr|table|ul|ol|li|img|h[1-6]|pre|script|iframe|svg|p|b|i|em|strong|form|input|button|br|section|article|header|footer|body|html|head|title|style|select|option|textarea|label|nav|main|figure|caption|code|small)\b/i.test(line)
    ) {
      if (!sanitizers.some((s) => line.includes(s))) {
        // The assignment TARGET is not interpolation: `msg += "<div>"` appends
        // a constant — the tainted accumulator being written is not the issue.
        const lhsMatch = line.match(
          /^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?:\+=|=)/,
        );
        const lineSansLhs = lhsMatch ? line.slice(line.indexOf(lhsMatch[0]) + lhsMatch[0].length) : line;
        for (const [name, tv] of taintedVars) {
          if (name.startsWith("__inline_")) continue;
          if (lhsMatch && lhsMatch[1].replace(/\s/g, "") === name) continue;
          const inter = new RegExp(
            `\\$\\{\\s*${identPat(name)}|\\+\\s*${identPat(name)}|${identPat(name)}\\s*\\+|,\\s*${identPat(name)}\\s*[,)]`,
          );
          if (!inter.test(lineSansLhs)) continue;
          const contextStart = Math.max(0, i - 1);
          const contextEnd = Math.min(lines.length - 1, i + 1);
          findings.push({
            cwe: "CWE-79",
            category: "Cross-Site Scripting",
            severity: "HIGH",
            owasp2021: "A03:2021",
            title: `Cross-Site Scripting: CWE-79 in ${filePath.split("/").pop()}`,
            description: `Tainted variable '${name}' interpolated into an HTML string at line ${lineNum} without encoding — the accumulator/response reaches the browser as markup (CWE-79).`,
            filePath,
            lineStart: tv.sourceLine,
            lineEnd: lineNum,
            codeSnippet: lines.slice(contextStart, contextEnd + 1).join("\n"),
            confidence: 80,
            source: tv.source,
            sink: "html-string-build",
            sanitizerFound: false,
            taintPath: [...tv.path, `HTML string build (line ${lineNum})`],
            detectionMethod: "TAINT",
          });
          break;
        }
      }
    }

    // Unvalidated dynamic dispatch: `obj[method](…)` with a TAINTED method
    // name invokes attacker-chosen code (CWE-94 / CWE-754 — the classic
    // `handler[method](msg)` RCE idiom). A whitelist membership check
    // (`hasOwnProperty`/`in`) on the same var anywhere in the file is the
    // accepted fix and suppresses the finding.
    if (
      (language === "javascript" || language === "typescript") &&
      taintedVars.size > 0
    ) {
      const masked = maskNonCode(line);
      for (const name of taintedVars.keys()) {
        if (name.startsWith("__inline_")) continue;
        const dd = new RegExp(
          `(?<![\\w$])[A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*\\s*\\[\\s*${escapeRegex(name)}\\s*\\]\\s*\\(`,
        );
        if (!dd.test(masked)) continue;
        const whitelisted = new RegExp(
          `hasOwnProperty\\s*\\(\\s*${escapeRegex(name)}\\s*\\)|\\b${escapeRegex(name)}\\s+in\\s+[A-Za-z_$]`,
        ).test(fileContent);
        if (whitelisted) continue;
        const contextStart = Math.max(0, i - 1);
        const contextEnd = Math.min(lines.length - 1, i + 1);
        findings.push({
          cwe: "CWE-94",
          category: "Code Injection",
          severity: "CRITICAL",
          owasp2021: "A03:2021",
          title: `Code Injection: CWE-94 in ${filePath.split("/").pop()}`,
          description: `Unvalidated dynamic method call: the tainted variable '${name}' selects the invoked method at line ${lineNum} without a whitelist check — attacker-controlled dispatch (CWE-94/CWE-754).`,
          filePath,
          lineStart: taintedVars.get(name)!.sourceLine,
          lineEnd: lineNum,
          codeSnippet: lines.slice(contextStart, contextEnd + 1).join("\n"),
          confidence: 80,
          source: taintedVars.get(name)!.source,
          sink: `obj[${name}](…)`,
          sanitizerFound: false,
          taintPath: [
            ...taintedVars.get(name)!.path,
            `dynamic dispatch via [${name}] (line ${lineNum})`,
          ],
          detectionMethod: "TAINT",
        });
        break;
      }
    }
  }

  // Step 3b: Prototype pollution (CWE-915) — computed-key writes driven by a
  // for-in merge loop (`for (name in options) { target[name] = copy }` —
  // jQuery CVE-2019-11358) or by a path-walk over dot-split segments
  // (`const p = parts[i]; object[p] = value` — dot-prop CVE-2020-8116, mpath
  // CVE-2018-16490). The accepted fix is a key guard (`key !== '__proto__'`)
  // anywhere in the file, or null-prototype maps (`Object.create(null)`).
  if (language === "javascript" || language === "typescript") {
    // Guards are tested on COMMENT-STRIPPED content with string literals
    // INTACT: the `__proto__` guard lives inside a string literal (blanked by
    // maskNonCode) while jQuery's `Object.create( null )` false-guard lives
    // in a comment.
    const guardContent = fileContent
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .split("\n")
      .map((l) => l.replace(/\/\/.*$/, ""))
      .join("\n");
    const protoGuarded =
      /__proto__/.test(guardContent) ||
      /Object\.create\s*\(\s*null\s*\)/.test(guardContent);
    if (!protoGuarded) {
      let ppLine = -1;
      let ppDesc = "";
      for (let i = 0; i < lines.length && ppLine < 0; i++) {
        const masked = maskNonCode(lines[i]);
        // T1: for-in merge loop.
        const forIn = masked.match(
          /\bfor\s*\(\s*(?:let\s+|const\s+|var\s+)?([A-Za-z_$][\w$]*)\s+in\s+[A-Za-z_$]/,
        );
        if (forIn) {
          const key = forIn[1];
          if (process.env.PP_DEBUG) console.error(`PP-T1 forIn '${key}' @${i + 1}`);
          const writeRe = new RegExp(
            `\\b([A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*)\\s*\\[\\s*${escapeRegex(key)}\\s*\\]\\s*=[^=]`,
          );
          for (let k = i + 1; k < Math.min(lines.length, i + 35); k++) {
            const wline = maskNonCode(lines[k]);
            const wm = wline.match(writeRe);
            if (wm) {
              // In-place normalization is NOT a merge: `offer[key] =
              // [].concat(offer[key])` rewrites each own key in place — no
              // second object is merged in (content-type's post loop).
              const rhs = wline.slice(wline.indexOf(wm[0]) + wm[0].length);
              const sameObj = new RegExp(
                `\\b${escapeRegex(wm[1].replace(/\s/g, ""))}\\s*\\[\\s*${escapeRegex(key)}\\s*\\]`,
              );
              if (sameObj.test(rhs)) continue;
              ppLine = k + 1;
              ppDesc = `merge loop writes target[${key}] with a key from an attacker-supplied object`;
              break;
            }
          }
        }
        if (ppLine >= 0) break;
        // T2: path-walk — segment extracted from an indexed array inside a
        // loop, then used as a computed write key. Requires a dot-split
        // somewhere in the file (the path parsing side).
        if (!/\.split\s*\(\s*['"]\./.test(guardContent)) continue;
        const idx = masked.match(
          /\b(?:(?:let|const|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*;?\s*$/,
        );
        if (idx) {
          const seg = idx[1];
          const writeRe = new RegExp(
            `\\b[A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*\\s*\\[\\s*${escapeRegex(seg)}\\s*\\]\\s*=[^=]`,
          );
          for (let k = i + 1; k < Math.min(lines.length, i + 45); k++) {
            if (writeRe.test(maskNonCode(lines[k]))) {
              ppLine = k + 1;
              ppDesc = `path-walk writes object[${seg}] with a segment from a dot-split path`;
              break;
            }
          }
        }
      }
      if (ppLine >= 0) {
        const contextStart = Math.max(0, ppLine - 2);
        const contextEnd = Math.min(lines.length - 1, ppLine);
        findings.push({
          cwe: "CWE-915",
          category: "Prototype Pollution",
          severity: "HIGH",
          owasp2021: "A08:2021",
          title: `Prototype Pollution: CWE-915 in ${filePath.split("/").pop()}`,
          description:
            `Prototype pollution: ${ppDesc} at line ${ppLine} in ${filePath}, ` +
            `with no __proto__/constructor key guard or null-prototype map. ` +
            `Keys like "__proto__" let attackers modify Object.prototype. ` +
            `CWE: CWE-915 | OWASP: A08:2021`,
          filePath,
          lineStart: ppLine,
          lineEnd: ppLine,
          codeSnippet: lines.slice(contextStart, contextEnd + 1).join("\n"),
          confidence: 80,
          source: "computed-key-write",
          sink: "obj[key] =",
          sanitizerFound: false,
          taintPath: [`computed-key write without proto guard (line ${ppLine})`],
          detectionMethod: "TAINT",
        });
      }
    }
  }

  // Step 4: Inter-procedural sink detection (JS/TS) — a tainted value passed to
  // a LOCAL function reaches a sink inside that callee. Single-level and
  // conservative: only named functions defined in this file, only word-boundary
  // argument references, and never re-entrant (calls inside the callee's own
  // body are excluded). This is the dominant FN pattern of the OpenSSF CVE
  // Benchmark (route handler → helper → sink).
  if (
    (language === "javascript" || language === "typescript") &&
    taintedVars.size > 0
  ) {
    const fnIndex = indexLocalFunctions(lines);
    if (fnIndex.size > 0) {
      for (let i = 0; i < lines.length; i++) {
        const masked = maskNonCode(lines[i]);
        if (/^\s*\/\//.test(masked)) continue;
        const callRe = /\b([A-Za-z_$][\w$]*)\s*\(([^;{}]*)\)/g;
        let cm: RegExpExecArray | null;
        while ((cm = callRe.exec(masked)) !== null) {
          const fn = fnIndex.get(cm[1]);
          if (!fn) continue;
          if (i >= fn.start && i <= fn.end) continue; // definition site / recursion
          const args = splitTopLevelArgs(cm[2]);
          if (args.length === 0) continue;
          // Bind tainted arguments to the corresponding parameters.
          const bound = new Map<string, TaintedVar>();
          args.forEach((arg, idx) => {
            const param = fn.params[idx];
            if (!param) return;
            for (const [, tv] of taintedVars) {
              if (tv.name.startsWith("__inline_")) continue;
              if (identRegex(tv.name).test(arg)) {
                bound.set(param, {
                  name: param,
                  sourceLine: tv.sourceLine,
                  source: tv.source,
                  path: [
                    ...tv.path,
                    `${fn.name}(${param} ⇐ tainted arg) (line ${i + 1})`,
                  ],
                });
                break;
              }
            }
            // Inline source directly in the argument (e.g. helper(req.query.x)).
            if (
              !bound.has(param) &&
              sources.some((s) => indexOfSourceToken(arg, s) >= 0)
            ) {
              bound.set(param, {
                name: param,
                sourceLine: i + 1,
                source: "inline",
                path: [`SOURCE inline in call to ${fn.name} (line ${i + 1})`],
              });
            }
          });
          if (bound.size === 0) continue;
          // Validated upstream: sanitizer on the call line or in any bound path.
          if (sanitizers.some((s) => lines[i].includes(s))) continue;
          if (
            [...bound.values()].some((tv) =>
              tv.path.some((p) => sanitizers.some((s) => p.includes(s))),
            )
          )
            continue;

          const hit = calleeSinkHit(
            fn,
            bound,
            compiledSinks,
            sanitizers,
            lines,
            fnIndex,
          );
          if (hit) {
            const contextStart = Math.max(0, hit.line - 3);
            const contextEnd = Math.min(lines.length - 1, hit.line + 1);
            findings.push({
              cwe: hit.sink.cwe,
              category: hit.sink.category,
              severity: hit.sink.severity as TaintFinding["severity"],
              owasp2021: hit.sink.owasp2021,
              title: `${hit.sink.category}: ${hit.sink.cwe} in ${filePath.split("/").pop()}`,
              description:
                `Taint analysis detected unsanitized data flow across functions: ` +
                `user input from "${hit.tv.source}" (line ${hit.tv.sourceLine}) is passed to ` +
                `${fn.name}() at line ${i + 1} and reaches the ${hit.sink.category.toLowerCase()} ` +
                `sink at line ${hit.line} inside ${fn.name} without sanitization.`,
              filePath,
              lineStart: hit.tv.sourceLine,
              lineEnd: hit.line,
              codeSnippet: lines.slice(contextStart, contextEnd + 1).join("\n"),
              confidence: 80,
              source: hit.tv.source,
              sink: hit.sink.pattern,
              sanitizerFound: false,
              taintPath: [
                ...hit.tv.path,
                `SINK: ${hit.sink.pattern} (line ${hit.line}, in ${fn.name})`,
              ],
              detectionMethod: "TAINT",
            });
          }
        }
      }
    }
  }

  // Deduplicate findings by CWE + line range
  return deduplicateFindings(findings);
}

// ==================== RULE FILTERING & TAINT PROPAGATION ====================

/**
 * Generic (`*`) keyword sources that are far too common as ordinary variable
 * names to be usable as substring/whole-token taint sources — `args` matches a
 * local `String[] args`, `body`/`query`/`params`/`input`/`request` match countless
 * benign identifiers. They cause large numbers of false positives (e.g. the OWASP
 * Benchmark safe cases). The precise per-language sources (Java `getParameter(`,
 * the JS/PHP/Ruby/Go API accessors, plus `argv`/`stdin`/`getenv`/`scanf`/`gets`)
 * cover real input APIs without the noise.
 */
const NOISY_GENERIC_SOURCES = new Set([
  "request",
  "input",
  "params",
  "query",
  "body",
  "args",
]);

/** Select the sources/sinks/sanitizers that apply to a language (or generic `*`). */
function filterRules(
  language: string,
  rules: TaintRulesBundle,
): { sources: string[]; sinks: DbTaintSink[]; sanitizers: string[] } {
  const lang = language.toLowerCase();
  const sources = rules.sources
    .filter((s) => s.language === lang || s.language === "*")
    .filter(
      (s) => !(s.language === "*" && NOISY_GENERIC_SOURCES.has(s.pattern)),
    )
    .map((s) => s.pattern);
  const sinks = rules.sinks.filter(
    (s) => s.language === lang || s.language === "*",
  );
  const sanitizers = rules.sanitizers
    .filter((s) => s.language === lang || s.language === "*")
    .map((s) => s.pattern);
  return { sources, sinks, sanitizers };
}

/**
 * Compute the set of tainted variables for a file: trace data flow from sources
 * (user input) through assignments and collection iteration to every variable
 * that may carry user-controlled data, dropping taint where a sanitizer applies.
 *
 * Shared by `runTaintAnalysis` (which then matches sinks against this set) and by
 * `computeTaintedVarNames` (used by the weakness engine for trust-boundary checks).
 */
function computeTaintPropagation(
  lines: string[],
  language: string,
  sources: string[],
  sanitizers: string[],
  skipEvents?: Set<string>,
): {
  vars: Map<string, TaintedVar>;
  collections: Map<string, TaintedVar>;
  inertElements: Set<string>;
  props: Set<string>;
} {
  const taintedVars: Map<string, TaintedVar> = new Map();
  // Tainted instance properties: `this.x = <attacker input>` stores taint on the
  // object; any later read of `this.x` carries it (class-based JS/TS libraries).
  const taintedProps = new Set<string>();
  // Track tainted map keys for HashMap put/get propagation (e.g., map.put("key", param) → map["key"] tainted)
  const taintedMapKeys: Map<string, TaintedVar> = new Map();
  // Track tainted collections (List/Set) — only used for CWE-78 sink detection.
  const taintedCollections: Map<string, TaintedVar> = new Map();
  // Index-aware element models for list-like collections (see ListElement).
  // A collection only gets a model while every mutation is understood
  // (add/remove/set/clear); an unrecognized mutation drops the model and the
  // engine falls back to the conservative whole-collection behavior.
  const listModels: Map<string, ListElement[]> = new Map();
  // Inert-document model: documents created via
  // `document.implementation.createHTMLDocument()` are detached (scripts cannot
  // execute), and elements created from them inherit that safety. Sanitizer
  // libraries use this to neutralize HTML before inserting it into the live DOM.
  const inertDocs = new Set<string>();
  const inertElements = new Set<string>();
  const dbState: DeadBranchState = {
    dead: false,
    kind: "none",
    switchValue: null,
    caseLive: false,
    braceDepth: 0,
  };

  // Pre-scan: identify inner-class methods that do NOT propagate taint from their
  // parameter to the return value. The OWASP Benchmark uses `doSomething(request, param)`
  // in ~50% of its cases; FALSE variants overwrite the param with a safe value inside.
  const { safeMethods, safeRanges } = findSafeInnerMethods(lines, sanitizers);

  // Pre-scan (JS/TS): local function index for inter-procedural return-taint
  // precision — `x = helper(tainted)` only propagates when helper provably
  // returns data derived from its parameter (see calleeReturnsTaint).
  const fnIndex =
    language === "javascript" || language === "typescript"
      ? indexLocalFunctions(lines)
      : null;

  // Pre-scan (JS/TS): parameters of EXPORTED functions are untrusted input.
  // Real-world library vulnerabilities (the bulk of the OpenSSF CVE Benchmark)
  // enter through the public API surface — `exports.findLoad = function (arg, cb)`
  // — not through Express-style `req.query`. Seeding exported parameters as
  // tainted models exactly that trust boundary. Restricted to JS/TS: in Java the
  // servlet `request` object is already covered by precise API sources, and
  // tainting every public-method parameter would break the safe-method analysis.
  if (language === "javascript" || language === "typescript") {
    // Response handles and callbacks are NOT attacker input: `res.end()`
    // scanning would otherwise find the tainted `res` var on the sink line
    // itself and fire with no tainted argument.
    const NOT_INPUT =
      /^(?:res|response|reply|resp|next|cb|callback|done|err|error|reject|resolve)$/;
    for (const p of findExportedFunctionParams(lines)) {
      if (NOT_INPUT.test(p.name)) continue;
      if (taintedVars.has(p.name)) continue;
      taintedVars.set(p.name, {
        name: p.name,
        sourceLine: p.line,
        source: "exported-function-parameter",
        path: [`exported function parameter ${p.name} (line ${p.line})`],
      });
    }
    // HTTP route handlers: `function (request, response, details)` — the request
    // object and route-capture params are remote input (CVE-2017-16084 et al.).
    for (const p of findRouteHandlerParams(lines)) {
      if (taintedVars.has(p.name)) continue;
      taintedVars.set(p.name, {
        name: p.name,
        sourceLine: p.line,
        source: "route-handler-parameter",
        path: [`route handler parameter ${p.name} (line ${p.line})`],
      });
    }
    // Event-emitter handlers: `.on("data", buf => …)` / `.on("message", fn)`
    // deliver attacker-controlled input from network streams (socket/ws/net).
    for (const p of findEventHandlerParams(lines, skipEvents)) {
      if (taintedVars.has(p.name)) continue;
      taintedVars.set(p.name, {
        name: p.name,
        sourceLine: p.line,
        source: "event-handler-parameter",
        path: [`event handler parameter ${p.name} (line ${p.line})`],
      });
    }
    // Property taint seed: `this.x = <exported/route/event param>` stores
    // attacker data on the instance. Fixpoint over `this.y = this.x` chains.
    {
      const seedNames = [...taintedVars.keys()].filter(
        (n) => !n.startsWith("__inline_"),
      );
      let grew = true;
      for (let pass = 0; pass < 3 && grew; pass++) {
        grew = false;
        for (let i = 0; i < lines.length; i++) {
          const masked = maskNonCode(lines[i]);
          for (const pm of masked.matchAll(
            /\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+)/g,
          )) {
            const [, prop, rhs] = pm;
            if (taintedProps.has(prop)) continue;
            for (const seed of seedNames) {
              if (identRegex(seed).test(rhs)) {
                taintedProps.add(prop);
                grew = true;
                break;
              }
            }
            if (!taintedProps.has(prop)) {
              const ref = rhs.match(/\bthis\s*\.\s*([A-Za-z_$][\w$]*)/);
              if (ref && taintedProps.has(ref[1])) {
                taintedProps.add(prop);
                grew = true;
              }
            }
          }
        }
      }
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip lines inside safe inner-method bodies — assignments there are in a
    // different scope and must not create tainted vars visible to the outer method.
    if (safeRanges.length > 0) {
      let inSafe = false;
      for (const [s, e] of safeRanges) {
        if (i >= s && i <= e) {
          inSafe = true;
          break;
        }
        if (s > i) break; // ranges are sorted
      }
      if (inSafe) continue;
    }

    // Skip comments
    if (
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("*") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("--")
    ) {
      continue;
    }

    // Update dead-branch state (multi-line if/else and switch tracking).
    updateDeadBranch(dbState, trimmed, lines, i);

    // Snapshot of tainted vars BEFORE this line's source detection. Step 1c must
    // only consider variables tainted on PRIOR lines — a variable born on this line
    // (Step 1) is not being "reassigned" and must not be killed.
    const taintedBeforeLine = new Set(taintedVars.keys());

    // Step 1: Detect sources — where tainted data enters
    for (const source of sources) {
      const srcIdx = indexOfSourceToken(line, source);
      if (srcIdx >= 0) {
        // Skip source matches inside string literals (e.g. error messages like
        // "getQueryString() couldn't find..."). Count unescaped quotes before the
        // match — an odd count means we're inside a string.
        let inString = false;
        for (let ci = 0; ci < srcIdx; ci++) {
          if (line[ci] === '"' && (ci === 0 || line[ci - 1] !== "\\"))
            inString = !inString;
        }
        if (inString) continue;
        // Taint only the variables ASSIGNED FROM this source: their `=` must appear
        // before the source (source is on the RHS). This stops a source keyword that
        // merely occurs on a line (e.g. `request` in a servlet method signature, or
        // `response.setContentType(..)`) from tainting unrelated variables.
        const assignedVars = collectAssignments(line, language)
          .filter((a) => a.idx < srcIdx)
          .map((a) => a.name);
        for (const varName of assignedVars) {
          taintedVars.set(varName, {
            name: varName,
            sourceLine: lineNum,
            source,
            path: [`${source} (line ${lineNum})`],
          });
        }
        // If the source is directly used in an expression (e.g., inline),
        // mark a pseudo-variable for the line
        if (assignedVars.length === 0) {
          taintedVars.set(`__inline_${lineNum}`, {
            name: `__inline_${lineNum}`,
            sourceLine: lineNum,
            source,
            path: [`${source} (line ${lineNum})`],
          });
        }
        break;
      }
    }

    // Step 1e: Validation-guard taint kill — `if (!isValidX(v)) { … return/throw … }`
    // is the canonical patch pattern for injection CVEs (e.g. dns-sync's fix for
    // CVE-2017-16100: `if (!isValidHostName(hostname)) return null;`). Once the
    // guard passes, `v` is considered validated. Restricted to functions whose
    // names signal validation (is*/validate*/check*/…) so existence/type probes
    // like `existsSync` do NOT masquerade as sanitizers.
    if (taintedVars.size > 0 && !dbState.dead) {
      const guard = maskNonCode(line).match(
        /\bif\s*\(\s*!?\s*((?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:is|validate|valid|check|assert|ensure|sanitize|verify)[A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\)/i,
      );
      if (guard && taintedVars.has(guard[2])) {
        // Confirm the guarded block exits (return/throw/continue/break) — a guard
        // that merely logs does not sanitize. Scan the same line, then ahead.
        let exits = /\b(return|throw|continue|break)\b/.test(
          line.slice(line.indexOf(guard[0]) + guard[0].length),
        );
        if (!exits) {
          let depth = 0;
          for (const ch of line) {
            if (ch === "{") depth++;
            else if (ch === "}") depth--;
          }
          for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
            const ahead = maskNonCode(lines[i + k]);
            if (/\b(return|throw|continue|break)\b/.test(ahead)) {
              exits = true;
              break;
            }
            for (const ch of ahead) {
              if (ch === "{") depth++;
              else if (ch === "}") depth--;
            }
          }
        }
        if (exits) taintedVars.delete(guard[2]);
      }

      // Path-escape guard: `if (…relative(…).indexOf('..')…) { …return… }` is the
      // canonical path-traversal patch (CVE-2017-16084 post). Any tainted var in
      // the condition is considered confined to its base directory afterwards.
      // The literal may appear as '..', '../', '/..' or '/../' (CVE-2018-16479).
      // NOTE: raw line — maskNonCode blanks string contents, which are the
      // very thing these guards match on. Two idioms: string-literal checks
      // (`indexOf('..')`) and regex-literal checks (`p.match(/(^|\/)\.\.(\/|$)/)`
      // — node-tar's CVE-2018-20834 fix).
      const escGuard =
        line.match(
          /\bif\s*\(.+(?:indexOf|includes|startsWith|contains)\s*\(\s*['"]\/?\.\.\/?['"]/,
        ) ??
        line.match(
          /\bif\s*\(.+\.(?:match|test|search)\s*\(\s*\/(?:[^/\\]|\\.)*(?:\\?\.){2}(?:[^/\\]|\\.)*\//,
        );
      if (escGuard) {
        let exits = /\b(return|throw|continue|break)\b/.test(
          line.slice(line.indexOf(escGuard[0]) + escGuard[0].length),
        );
        if (!exits) {
          let depth = 0;
          for (const ch of line) {
            if (ch === "{") depth++;
            else if (ch === "}") depth--;
          }
          for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
            const ahead = maskNonCode(lines[i + k]);
            if (/\b(return|throw|continue|break)\b/.test(ahead)) {
              exits = true;
              break;
            }
            for (const ch of ahead) {
              if (ch === "{") depth++;
              else if (ch === "}") depth--;
            }
          }
        }
        if (exits) {
          const cond = line.slice(line.indexOf(escGuard[0]));
          for (const name of [...taintedVars.keys()]) {
            if (name.startsWith("__inline_")) continue;
            if (identRegex(name).test(cond))
              taintedVars.delete(name);
          }
        }
      }

      // Base-directory confinement check: `if (…x.indexOf(base) !== 0…) return`
      // / `if (!x.startsWith(base)) return` — x is verified to live UNDER base,
      // so traversal payloads in x are inert afterwards (serve-static style,
      // CVE-2018-3712 post: `related.indexOf(current) !== 0`).
      const confGuard = maskNonCode(line).match(
        /\bif\s*\(.*?\b([A-Za-z_$][\w$]*)\s*\.\s*(indexOf|startsWith)\s*\(\s*[A-Za-z_$][\w$]*(?:\s*\.\s*[\w$]+)*\s*\)/,
      );
      if (
        confGuard &&
        (/!==?\s*0/.test(line) ||
          new RegExp(
            `!\\s*${escapeRegex(confGuard[1])}\\s*\\.\\s*startsWith`,
          ).test(maskNonCode(line)))
      ) {
        let exits = /\b(return|throw|continue|break)\b/.test(
          line.slice(line.indexOf(confGuard[0]) + confGuard[0].length),
        );
        if (!exits) {
          let depth = 0;
          for (const ch of line) {
            if (ch === "{") depth++;
            else if (ch === "}") depth--;
          }
          for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
            const ahead = maskNonCode(lines[i + k]);
            if (/\b(return|throw|continue|break)\b/.test(ahead)) {
              exits = true;
              break;
            }
            for (const ch of ahead) {
              if (ch === "{") depth++;
              else if (ch === "}") depth--;
            }
          }
        }
        if (exits && taintedVars.has(confGuard[1]))
          taintedVars.delete(confGuard[1]);
      }

      // Whitelist-format validation guard: `if (!/^\w+$/.test(x)) return` /
      // `if (!WHITELIST.test(x)) return` — an anchored whitelist regex verifies
      // the format; traversal/shell payloads cannot survive (CVE-2018-6342's
      // WINDOWS_FILE_NAME_WHITELIST fix). The regex must start with `^`
      // (inline literal or an anchored const).
      const wlGuard = line.match(
        /\bif\s*\(\s*!\s*(?:(\/\^[^/]*\/)|([A-Za-z_$][\w$]*))\s*\.\s*test\s*\(\s*([A-Za-z_$][\w$]*)/,
      );
      if (wlGuard) {
        let anchored = !!wlGuard[1];
        if (!anchored && wlGuard[2]) {
          const defRe = new RegExp(
            `(?:const|let|var)\\s+${escapeRegex(wlGuard[2])}\\s*=\\s*(?:new RegExp\\(['"\`]\\^|\\/\\^)`,
          );
          for (const l of lines) {
            if (defRe.test(l)) {
              anchored = true;
              break;
            }
          }
        }
        if (anchored) {
          let exits = /\b(return|throw|continue|break)\b/.test(
            line.slice(line.indexOf(wlGuard[0]) + wlGuard[0].length),
          );
          if (!exits) {
            let depth = 0;
            for (const ch of line) {
              if (ch === "{") depth++;
              else if (ch === "}") depth--;
            }
            for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
              const ahead = maskNonCode(lines[i + k]);
              if (/\b(return|throw|continue|break)\b/.test(ahead)) {
                exits = true;
                break;
              }
              for (const ch of ahead) {
                if (ch === "{") depth++;
                else if (ch === "}") depth--;
              }
            }
          }
          if (exits && taintedVars.has(wlGuard[3]))
            taintedVars.delete(wlGuard[3]);
        }
      }

      // Blacklist-char rejection: `if (x.indexOf('"') >= 0) throw …` rejects
      // values containing an injection-critical char (`"`/`'`/`<`/`>`/`\`),
      // neutralizing HTML-attribute/quote-injection payloads afterwards —
      // the canonical cheap fix for reflected XSS in response builders.
      // NOTE: raw line — the char literal is the thing being matched.
      const blackGuard = line.match(
        /\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*indexOf\s*\(\s*['"](?:["'<>\\])['"]\s*\)\s*(?:>=?\s*0|!==?\s*-1)/,
      );
      if (blackGuard && taintedVars.has(blackGuard[1])) {
        let exits = /\b(return|throw|continue|break)\b/.test(
          line.slice(line.indexOf(blackGuard[0]) + blackGuard[0].length),
        );
        if (!exits) {
          let depth = 0;
          for (const ch of line) {
            if (ch === "{") depth++;
            else if (ch === "}") depth--;
          }
          for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
            const ahead = maskNonCode(lines[i + k]);
            if (/\b(return|throw|continue|break)\b/.test(ahead)) {
              exits = true;
              break;
            }
            for (const ch of ahead) {
              if (ch === "{") depth++;
              else if (ch === "}") depth--;
            }
          }
        }
        if (exits) taintedVars.delete(blackGuard[1]);
      }

      // Strip-in-place neutralization: `x = x.replace('/../', '')` only fully
      // neutralizes traversal when it runs in a STRIP-UNTIL-CLEAN loop —
      // `while (x.indexOf('/../') != -1) { x = x.replace('/../', '') }`
      // (CVE-2018-16479: the vulnerable version stripped once without the loop,
      // leaving nested '....//' payloads; the patch loops until clean).
      {
        const strip = line.match(
          /\b([A-Za-z_$][\w$]*)\s*=\s*\1\s*\.\s*replace(?:All)?\s*\(\s*(?:['"]\/?\.\.\/?['"]|\/[^/]*\.\.[^/]*\/)/,
        );
        if (strip && taintedVars.has(strip[1])) {
          const loopCheck = new RegExp(
            `\\bwhile\\s*\\(.*\\b${escapeRegex(strip[1])}\\s*\\.\\s*(?:indexOf|includes)\\s*\\(\\s*['"]\\/?\\.\\.\\/?['"]`,
          );
          let inLoop = false;
          for (let k = 1; k <= 3 && i - k >= 0; k++) {
            if (loopCheck.test(lines[i - k])) {
              inLoop = true;
              break;
            }
          }
          if (inLoop) taintedVars.delete(strip[1]);
        }
      }
    }

    // Step 1d: List element model maintenance + index-aware `list.get(N)` resolution.
    // Runs on every line (even with no tainted vars yet) so the model reflects the
    // full add/remove history when a `get(N)` is reached. Assignments resolved here
    // are recorded in `listGetResolved` so Steps 1c/2 skip them (the blanket
    // `.get(\d+)` neutralization would otherwise kill legitimately-tainted reads).
    const listGetResolved = new Set<string>();
    {
      const masked = maskNonCode(line);
      // Declaration: `List<String> x = new ArrayList<>();` → fresh empty model.
      const declMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*new\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:ArrayList|LinkedList|Vector|CopyOnWriteArrayList)\s*[<(]/,
      );
      if (declMatch) listModels.set(declMatch[1], []);
      // Mutations.
      const addMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*add\s*\((.+)\)/,
      );
      if (addMatch && listModels.has(addMatch[1])) {
        const argExpr = addMatch[2];
        let element: ListElement = null;
        for (const [, tv] of taintedVars) {
          if (tv.name.startsWith("__inline_")) continue;
          if (identRegex(tv.name).test(argExpr)) {
            element = tv;
            break;
          }
        }
        listModels.get(addMatch[1])!.push(element);
      }
      const removeMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*remove\s*\(\s*(\d+)\s*\)/,
      );
      if (removeMatch && listModels.has(removeMatch[1])) {
        listModels.get(removeMatch[1])!.splice(parseInt(removeMatch[2], 10), 1);
      }
      const setMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*set\s*\(\s*(\d+)\s*,(.+)\)/,
      );
      if (setMatch && listModels.has(setMatch[1])) {
        const model = listModels.get(setMatch[1])!;
        const idx = parseInt(setMatch[2], 10);
        if (idx >= 0 && idx < model.length) {
          let element: ListElement = null;
          for (const [, tv] of taintedVars) {
            if (tv.name.startsWith("__inline_")) continue;
            if (identRegex(tv.name).test(setMatch[3])) {
              element = tv;
              break;
            }
          }
          model[idx] = element;
        }
      }
      if (/\b[A-Za-z_$][\w$]*\s*\.\s*clear\s*\(\s*\)/.test(masked)) {
        const clearMatch = masked.match(
          /\b([A-Za-z_$][\w$]*)\s*\.\s*clear\s*\(\s*\)/,
        );
        if (clearMatch && listModels.has(clearMatch[1]))
          listModels.set(clearMatch[1], []);
      }
      // Unrecognized bulk mutations (addAll, removeIf, retainAll, …) drop the model.
      const bulkMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:addAll|removeAll|retainAll|removeIf|replaceAll|sort)\s*\(/,
      );
      if (bulkMatch) listModels.delete(bulkMatch[1]);

      // Inert-document tracking (see declaration above).
      const inertDocMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*document\s*\.\s*implementation\s*\.\s*createHTMLDocument\s*\(/,
      );
      if (inertDocMatch) inertDocs.add(inertDocMatch[1]);
      const elMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*createElement\s*\(/,
      );
      if (elMatch && inertDocs.has(elMatch[2])) inertElements.add(elMatch[1]);

      // Iteration propagation (JS/TS): `for (const x of/in tainted)` taints the
      // loop variable; `tainted.forEach((x) => …)` / `.map(x => …)` taint the
      // callback parameter (Cyclone's `for (const enc in encodings)` —
      // CVE-2019-15532; public.js's `files.forEach(function (file)` —
      // CVE-2018-16480).
      if (language === "javascript" || language === "typescript") {
        const taintIterVar = (varName: string, srcExpr: string): void => {
          if (taintedVars.has(varName)) return;
          for (const [, tv] of taintedVars) {
            if (tv.name.startsWith("__inline_")) continue;
            if (identRegex(tv.name).test(srcExpr)) {
              taintedVars.set(varName, {
                name: varName,
                sourceLine: lineNum,
                source: `iteration over tainted ${tv.name}`,
                path: [...tv.path, `${varName} iterated from ${tv.name} (line ${lineNum})`],
              });
              break;
            }
          }
        };
        const iterMatch = masked.match(
          /\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+(?:in|of)\s+([^)]+)\)/,
        );
        if (iterMatch) taintIterVar(iterMatch[1], iterMatch[2]);
        const eachMatch = masked.match(
          /\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*(?:forEach|map|filter|each)\s*\(\s*(?:async\s+)?(?:function\s*[A-Za-z_$\w$]*\s*)?\(\s*([A-Za-z_$][\w$]*)/,
        );
        if (eachMatch) taintIterVar(eachMatch[2], eachMatch[1]);

        // Filesystem content propagation: reading a TAINTED path yields tainted
        // content — the directory listing / file bytes are attacker-influenced
        // (stored-XSS via filenames in directory listings — CVE-2018-16480).
        const fsCb = masked.match(
          /\bfs\s*\.\s*(?:readdir|readFile)\s*\(\s*([^,]+?)\s*,\s*(?:function\s*[A-Za-z_$\w$]*\s*)?\(\s*[A-Za-z_$][\w$]*\s*,\s*([A-Za-z_$][\w$]*)/,
        );
        if (fsCb) taintIterVar(fsCb[2], fsCb[1]);
        const fsSync = masked.match(
          /\b([A-Za-z_$][\w$]*)\s*=\s*fs\s*\.\s*(?:readdirSync|readFileSync)\s*\(\s*([^)]*)\)/,
        );
        if (fsSync) taintIterVar(fsSync[1], fsSync[2]);

        // Array accumulation: `parts.push(tainted)` taints the array —
        // `list.push('<li>', file, …)` then `res.end(list.join())`.
        const pushMatch = masked.match(
          /\b([A-Za-z_$][\w$]*)\s*\.\s*push\s*\((.+)\)\s*;?\s*$/,
        );
        if (pushMatch) taintIterVar(pushMatch[1], pushMatch[2]);
      }

      // Index-aware read: `x = list.get(N)` (optionally with a cast).
      const getIdxMatch = masked.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*(?:\([\w$.[\]]*\)\s*)?([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*(\d+)\s*\)/,
      );
      if (getIdxMatch && !dbState.dead) {
        const [, target, collName, idxRaw] = getIdxMatch;
        const model = listModels.get(collName);
        const idx = parseInt(idxRaw, 10);
        if (model && idx >= 0 && idx < model.length) {
          listGetResolved.add(target);
          const element = model[idx];
          if (element) {
            taintedVars.set(target, {
              name: target,
              sourceLine: element.sourceLine,
              source: element.source,
              path: [
                ...element.path,
                `${target} = ${collName}.get(${idx}) (line ${lineNum})`,
              ],
            });
          } else {
            // Provably-untainted element (literal/clean value) → safe read.
            taintedVars.delete(target);
          }
        }
      }
    }

    // Step 1c + Step 2: Neutralization-aware taint propagation with dead-branch guard.
    //
    // The OWASP Benchmark "false" cases deliberately route the tainted value through
    // a construct that does NOT actually carry it to the sink:
    //   - always-true/false ternary (`bar = cond ? "safe" : param;`)
    //   - always-true if/else (`if (const) bar = "safe"; else bar = param;`)
    //   - switch on constant target (dead cases contain `bar = param`)
    //
    // Step 1c: if an already-tainted var is reassigned to a constant (no tainted var
    // in RHS), KILL its taint — unless we're in a dead branch (assignment won't execute).
    // Step 2: propagate taint to new vars, but BLOCK if the RHS is neutralized or the
    // assignment is in a dead branch.
    if (taintedVars.size > 0) {
      const assignments = collectAssignments(line, language);

      // Property write: `this.x = <tainted var>` stores taint on the instance
      // (e.g. a constructor/setter receiving an exported API parameter).
      for (const pm of maskNonCode(line).matchAll(
        /\bthis\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+)/g,
      )) {
        if (taintedProps.has(pm[1])) continue;
        for (const [name] of taintedVars) {
          if (name.startsWith("__inline_")) continue;
          if (identRegex(name).test(pm[2])) {
            taintedProps.add(pm[1]);
            break;
          }
        }
      }

      // Step 1c: kill taint on constant reassignment of an already-tainted var.
      // Gated on NOT being in a dead branch — a dead assignment doesn't execute.
      if (taintedBeforeLine.size > 0 && !dbState.dead) {
        for (const a of assignments) {
          if (listGetResolved.has(a.name)) continue; // resolved index-aware in Step 1d
          if (!taintedBeforeLine.has(a.name)) continue; // born this line by Step 1
          if (!taintedVars.has(a.name)) continue;
          // Skip assignments in the dead else portion of a single-line if/else.
          if (isInDeadSingleLineElse(line, a.idx, lines, i)) continue;
          const rhs = line.slice(a.idx + 1);
          // Reassignment through an encoding/sanitizing call neutralizes the
          // target: `item = htmlsafe(item)` / `x = escape(x)` — covers LOCAL
          // sanitizer helpers unknown to the DB (serve-index's htmlsafe).
          if (
            taintedVars.has(a.name) &&
            (sanitizers.some((s) => rhs.includes(s)) ||
              /\b(?:escape\w*|sanitize\w*|encodeURI\w*|clean\w*|purify\w*|htmlsafe)\s*\(/i.test(rhs))
          ) {
            taintedVars.delete(a.name);
            continue;
          }
          if (isNeutralizedRhs(rhs, taintedVars, lines, i))
            taintedVars.delete(a.name);
        }
      }

      // Step 2: propagate taint through assignments (with neutralization + dead-branch guard).
      if (!dbState.dead) {
        for (const a of assignments) {
          if (listGetResolved.has(a.name)) continue; // resolved index-aware in Step 1d
          if (taintedVars.has(a.name)) continue; // already tainted
          // Skip assignments in the dead else portion of a single-line if/else.
          if (isInDeadSingleLineElse(line, a.idx, lines, i)) continue;
          // If the RHS is neutralized (constant / dead-branch ternary), do NOT propagate.
          let rhs = line.slice(a.idx + 1);
          // Multi-line template literal RHS: `const msg = `…\n…${tainted}…``
          // — join until the closing backtick so the interpolation is visible.
          const openedTemplate =
            (rhs.match(/`/g) ?? []).length % 2 === 1;
          if (openedTemplate) {
            for (let k = i + 1; k < Math.min(lines.length, i + 15); k++) {
              rhs += "\n" + lines[k];
              if ((rhs.match(/`/g) ?? []).length % 2 === 0) break;
            }
          }
          if (isNeutralizedRhs(rhs, taintedVars, lines, i)) continue;
          // Property read: RHS referencing a tainted property (`this.x`) taints
          // the LHS — the value was stored by a constructor/setter from input.
          let propSrc: string | null = null;
          for (const prop of taintedProps) {
            if (
              new RegExp(`\\bthis\\s*\\.\\s*${escapeRegex(prop)}\\b`).test(rhs)
            ) {
              propSrc = prop;
              break;
            }
          }
          if (propSrc) {
            taintedVars.set(a.name, {
              name: a.name,
              sourceLine: lineNum,
              source: "tainted-property",
              path: [
                `tainted property this.${propSrc}`,
                `${a.name} = this.${propSrc} (line ${lineNum})`,
              ],
            });
            continue;
          }
          // If the assignment is from a safe inner-class method call (one that
          // provably does NOT propagate taint from its param to the return value),
          // do NOT propagate. This handles the OWASP `doSomething` pattern.
          // Matches both `obj.doSomething(...)` and direct `doSomething(...)`.
          if (safeMethods.size > 0) {
            const methodCall = rhs.match(
              /(?:^\s*|\.\s*|\bnew\s+[\w$.]+\s*\.\s*)([A-Za-z_$][\w$]*)\s*\(/,
            );
            if (methodCall && safeMethods.has(methodCall[1])) continue;
          }
          // Inter-procedural return-taint precision (JS/TS): when the WHOLE RHS
          // is a single call to a local function and the tainted reference(s)
          // are its argument(s), propagate ONLY if the callee's return value is
          // derived from the bound parameter. Kills FPs of the form
          // `out = format(tainted)` where format() builds a constant from
          // scratch (the patched variants of XSS/cmdi CVEs).
          if (fnIndex && fnIndex.size > 0) {
            const callOnly = rhs
              .replace(/^\s*=\s*/, "")
              .trim()
              .match(/^(?:await\s+)?([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*$/);
            if (callOnly) {
              const fn = fnIndex.get(callOnly[1]);
              if (fn && !(i >= fn.start && i <= fn.end)) {
                const args = splitTopLevelArgs(callOnly[2]);
                const bound = new Set<string>();
                let anyTaintedArg = false;
                args.forEach((arg, idx) => {
                  const param = fn.params[idx];
                  if (!param) return;
                  for (const [, tv] of taintedVars) {
                    if (tv.name.startsWith("__inline_")) continue;
                    if (identRegex(tv.name).test(arg)) {
                      bound.add(param);
                      anyTaintedArg = true;
                      break;
                    }
                  }
                });
                // Known callee + tainted args + provably clean return → no propagation.
                if (
                  anyTaintedArg &&
                  !calleeReturnsTaint(fn, bound, lines, sanitizers)
                )
                  continue;
              }
            }
          }
          // Check if a tainted var appears on this line (or the next few lines for
          // multiline assignments like `bar =\n  new String(... param ...)`).
          // Use word-boundary regex to avoid substring false matches (e.g., 'i' in 'String').
          const rhsTrimmed = rhs
            .replace(/^\s*=\s*/, "")
            .replace(/;\s*$/, "")
            .trim();
          const isMultiline =
            rhsTrimmed === "" ||
            hasUnclosedParen(rhsTrimmed) ||
            // Template literal opened but not closed on this line —
            // `const msg = `…` continues on the following lines (CVE-2019-15479).
            openedTemplate;
          // Match against the masked line: a tainted var name that only appears
          // inside a string literal or comment is not a data-flow reference.
          const maskedLine = maskNonCode(line);
          for (const [, tv] of taintedVars) {
            const tvRegex = identRegex(tv.name);
            let found =
              tvRegex.test(maskedLine) && !maskedLine.includes(tv.name + " =");
            // Template-literal RHS joined across lines: the interpolation is
            // code (maskNonCode does not blank backtick contents).
            if (!found && openedTemplate) found = tvRegex.test(rhs);
            // Multiline lookahead: check next lines for the tainted var.
            if (!found && isMultiline) {
              let depth = 0;
              for (let k = 1; k <= 8 && i + k < lines.length; k++) {
                const ahead = maskNonCode(lines[i + k]);
                if (tvRegex.test(ahead)) {
                  found = true;
                  break;
                }
                // An open template literal ENDS at the next line carrying a
                // closing backtick — scanning past it crosses statements
                // (CVE-2019-15479 post FP).
                if (openedTemplate && (lines[i + k].match(/`/g) ?? []).length % 2 === 1)
                  break;
                // Track paren depth; stop when the opened call/expression closes.
                for (const ch of ahead) {
                  if (ch === "(") depth++;
                  else if (ch === ")") depth--;
                }
                if (depth < 0) break; // closed the opening paren from the assignment
              }
            }
            if (found) {
              const sanitized = sanitizers.some((s) => line.includes(s));
              if (!sanitized) {
                taintedVars.set(a.name, {
                  name: a.name,
                  sourceLine: tv.sourceLine,
                  source: tv.source,
                  path: [...tv.path, `${a.name} = ... (line ${lineNum})`],
                });
              }
              break;
            }
          }
        }
      }
    }

    // Step 2b: Collection iteration — `for (Type elem : collection)` (Java
    // enhanced-for) or `for elem in collection` (Python/Ruby). If the collection
    // is tainted, each iterated element carries the taint (e.g. OWASP's
    // `theCookies = request.getCookies()` → `for (Cookie theCookie : theCookies)`
    // → `theCookie.getValue()`).
    if (taintedVars.size > 0) {
      const forEach =
        line.match(
          /for\s*\(\s*(?:[\w$.]+\s+)?([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*\)/,
        ) || line.match(/for\s+([A-Za-z_$][\w$]*)\s+in\s+([A-Za-z_$][\w$]*)/);
      if (forEach) {
        const [, elem, collection] = forEach;
        const tv = taintedVars.get(collection);
        if (tv && !taintedVars.has(elem)) {
          const sanitized = sanitizers.some((s) => line.includes(s));
          if (!sanitized) {
            taintedVars.set(elem, {
              name: elem,
              sourceLine: tv.sourceLine,
              source: tv.source,
              path: [...tv.path, `${elem} ∈ ${collection} (line ${lineNum})`],
            });
          }
        }
      }
    }

    // Step 2c: ProcessBuilder command-list propagation — when a tainted variable
    // is added to a list that is then passed to `.command(...)`, the list carries
    // taint to the sink. We handle this at sink detection time by checking if any
    // tainted variable was added to a list argument passed to a command sink.
    // No global collection taint is set here (it causes too many FPs).

    // Step 2c-map: HashMap put/get key-aware propagation.
    // When `map.put("key", taintedVar)` is seen, record that map["key"] is tainted.
    // When `bar = map.get("key")` is seen with the SAME key, propagate taint to bar.
    // This handles the OWASP Benchmark pattern:
    //   map.put("keyB-123", param);  bar = (String) map.get("keyB-123");
    if (taintedVars.size > 0 && !dbState.dead) {
      // Detect map.put(KEY, value) — value can be a simple var or var.method()
      const putMatch = line.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\s*\)/,
      );
      if (putMatch) {
        const [, mapName, key, valExpr] = putMatch;
        // Check if the value expression contains a tainted variable (word-boundary match)
        for (const [, tv] of taintedVars) {
          if (tv.name.startsWith("__inline_")) continue;
          const valRe = identRegex(tv.name);
          if (valRe.test(valExpr)) {
            taintedMapKeys.set(`${mapName}[${key}]`, tv);
            break;
          }
        }
      }
      // Detect bar = map.get(KEY) with tainted key
      const getMatch = line.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*"([^"]+)"\s*\)/,
      );
      if (getMatch) {
        const [, mapName, key] = getMatch;
        const mapKey = `${mapName}[${key}]`;
        const tv = taintedMapKeys.get(mapKey);
        // Find the assigned variable
        const assignments = collectAssignments(line, language);
        for (const a of assignments) {
          if (tv) {
            // Tainted key → propagate taint
            if (taintedVars.has(a.name)) continue;
            const sanitized = sanitizers.some((s) => line.includes(s));
            if (!sanitized) {
              taintedVars.set(a.name, {
                name: a.name,
                sourceLine: tv.sourceLine,
                source: tv.source,
                path: [
                  ...tv.path,
                  `${a.name} = ${mapName}.get("${key}") (line ${lineNum})`,
                ],
              });
            }
          } else {
            // Non-tainted key → KILL existing taint (safe value overwrites)
            if (taintedVars.has(a.name)) {
              taintedVars.delete(a.name);
            }
          }
          break;
        }
      }
    }

    // Step 2d: Method-call-on-tainted-object propagation — when a tainted variable
    // is the RECEIVER of a method call whose result is assigned, the result inherits
    // taint (e.g. `name = (String) names.nextElement()` where `names` is tainted).
    if (taintedVars.size > 0 && !dbState.dead) {
      const assignments = collectAssignments(line, language);
      for (const a of assignments) {
        if (taintedVars.has(a.name)) continue; // already tainted
        const rhs = line.slice(a.idx + 1);
        // Check if RHS has `taintedVar.method(` pattern (tainted var as receiver).
        for (const [, tv] of taintedVars) {
          if (tv.name.startsWith("__inline_")) continue;
          const receiverRe = new RegExp(
            `\\b${escapeRegex(tv.name)}\\s*\\.\\s*[A-Za-z_$][\\w$]*\\s*\\(`,
          );
          if (receiverRe.test(rhs)) {
            const sanitized = sanitizers.some((s) => line.includes(s));
            if (!sanitized) {
              taintedVars.set(a.name, {
                name: a.name,
                sourceLine: tv.sourceLine,
                source: tv.source,
                path: [
                  ...tv.path,
                  `${a.name} = ${tv.name}.method() (line ${lineNum})`,
                ],
              });
            }
            break;
          }
        }
      }
    }

    // Step 2e: Tainted-argument propagation — when a tainted variable is passed as
    // an ARGUMENT to a method call whose result is assigned, the result inherits
    // taint (e.g. `bar = thing.doSomething(f70670)` where `f70670` is tainted).
    // This handles external method calls that propagate their argument to the return.
    // EXCEPTION: If the method is in `safeMethods` (provably does NOT propagate),
    // do NOT taint the result.
    if (taintedVars.size > 0 && !dbState.dead) {
      const assignments = collectAssignments(line, language);
      for (const a of assignments) {
        if (taintedVars.has(a.name)) continue; // already tainted
        const rhs = line.slice(a.idx + 1);
        // Check if RHS has a method call with a tainted argument.
        // Pattern: `something.method(... taintedVar ...)` or `new Type(... taintedVar ...)`
        const methodCallRe =
          /(?:[A-Za-z_$][\w$]*\s*\.\s*)?[A-Za-z_$][\w$]*\s*\(|new\s+[A-Za-z_$][\w$.]*\s*\(/;
        if (!methodCallRe.test(rhs)) continue;
        // Check if the method is known-safe (does not propagate taint).
        if (safeMethods.size > 0) {
          const methodCall = rhs.match(
            /(?:^\s*|\.\s*|\bnew\s+[\w$.]+\s*\.\s*)([A-Za-z_$][\w$]*)\s*\(/,
          );
          if (methodCall && safeMethods.has(methodCall[1])) continue;
        }
        for (const [, tv] of taintedVars) {
          if (tv.name.startsWith("__inline_")) continue;
          const argRe = new RegExp(
            `\\(\\s*[^)]*\\b${escapeRegex(tv.name)}\\b[^)]*\\)`,
          );
          if (argRe.test(rhs)) {
            const sanitized = sanitizers.some((s) => line.includes(s));
            if (!sanitized) {
              taintedVars.set(a.name, {
                name: a.name,
                sourceLine: tv.sourceLine,
                source: tv.source,
                path: [
                  ...tv.path,
                  `${a.name} = method(${tv.name}) (line ${lineNum})`,
                ],
              });
            }
            break;
          }
        }
      }
    }

    // Step 2f: Collection-add propagation — when a tainted variable appears in an
    // argument to `.add(...)` on a collection, the collection itself carries taint.
    // This handles the OWASP pattern:
    //   argList.add("echo " + bar);  ProcessBuilder pb = new ProcessBuilder(argList);
    // Collections are tracked SEPARATELY from taintedVars — they only trigger
    // CWE-78 (command injection) sinks, preventing FPs in other categories.
    if (taintedVars.size > 0 && !dbState.dead) {
      // `.add(x)` (Java collections) and `.push(x)` (JS arrays) both make the
      // collection carry taint for command-construction sinks (CWE-78).
      const addMatch = line.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:add|push)\s*\((.+)\)/,
      );
      if (addMatch) {
        const [, collName, addArg] = addMatch;
        if (!taintedCollections.has(collName)) {
          for (const [, tv] of taintedVars) {
            if (tv.name.startsWith("__inline_")) continue;
            const argRe = identRegex(tv.name);
            if (argRe.test(addArg)) {
              const sanitized = sanitizers.some((s) => line.includes(s));
              if (!sanitized) {
                taintedCollections.set(collName, {
                  name: collName,
                  sourceLine: tv.sourceLine,
                  source: tv.source,
                  path: [
                    ...tv.path,
                    `${collName}.add(...${tv.name}...) (line ${lineNum})`,
                  ],
                });
              }
              break;
            }
          }
        }
      }
    }
  }

  return {
    vars: taintedVars,
    collections: taintedCollections,
    inertElements,
    props: taintedProps,
  };
}

/**
 * Names of variables that carry user-controlled (tainted) data in a file.
 * Exposed for the weakness engine (e.g. trust-boundary detection: a tainted value
 * stored into an HTTP session). Inline pseudo-variables (`__inline_N`) are excluded.
 *
 * @param skipSanitizers When true, sanitizers are ignored — useful for trust-boundary
 *   detection where the concern is data provenance, not injection safety.
 */
export function computeTaintedVarNames(
  fileContent: string,
  language: string,
  rules: TaintRulesBundle,
  skipSanitizers = false,
): Set<string> {
  const { sources, sanitizers } = filterRules(language, rules);
  if (sources.length === 0) return new Set();
  const lines = fileContent.split("\n");
  const tainted = computeTaintPropagation(
    lines,
    language,
    sources,
    skipSanitizers ? [] : sanitizers,
  );
  const names = new Set<string>();
  for (const name of tainted.vars.keys()) {
    if (!name.startsWith("__inline_")) names.add(name);
  }
  return names;
}

// ==================== HELPERS ====================

/** Compile a pattern to a RegExp once (invalid patterns never throw at scan time). */
function toRegex(pattern: string): RegExp {
  try {
    return new RegExp(pattern);
  } catch {
    // Fall back to an escaped literal match if the pattern is not valid regex.
    return new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  }
}

/**
 * Index of `source` in `line` as a whole token, or -1 if absent. A "whole token"
 * match requires that the character before/after the match is not an identifier
 * character, so the broad keyword source "args" matches `args`/`args[0]` but NOT
 * `argsEnv`, and "input" matches `input` but NOT `userInput`. This is what keeps
 * the generic (`*`) sources from over-tainting unrelated variables that merely
 * contain the keyword as a substring (a major source of false positives).
 */
function indexOfSourceToken(line: string, source: string): number {
  let from = 0;
  while (from <= line.length - source.length) {
    const idx = line.indexOf(source, from);
    if (idx < 0) return -1;
    const before = idx > 0 ? line.charCodeAt(idx - 1) : 0;
    const after =
      idx + source.length < line.length
        ? line.charCodeAt(idx + source.length)
        : 0;
    const isWordChar = (c: number) =>
      (c >= 48 && c <= 57) ||
      (c >= 65 && c <= 90) ||
      (c >= 97 && c <= 122) ||
      c === 95;
    if (!isWordChar(before) && !isWordChar(after)) return idx;
    from = idx + 1;
  }
  return -1;
}

/** An assigned variable together with the index of its `=` in the line. The index
 * lets callers decide whether the variable is assigned *from* a source (the source
 * sits to the right of the `=`) versus merely co-occurring on the line. */
interface Assignment {
  name: string;
  idx: number;
}

function collectAssignments(line: string, language: string): Assignment[] {
  const out: Assignment[] = [];
  const KEYWORDS =
    /^(?:if|for|while|switch|return|catch|const|let|var|new|function|class|else|do|try|finally|throw)$/;
  const push = (name: string, idx: number) => {
    if (name && !KEYWORDS.test(name)) out.push({ name, idx });
  };

  // JS/TS: const/let/var x = ...
  for (const m of line.matchAll(/(?:const|let|var)\s+(\w+)\s*=/g))
    push(m[1], m.index! + m[0].length - 1);

  // Destructuring: const { a, b } = ...
  const destructMatch = line.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=/);
  if (destructMatch) {
    const eqIdx = destructMatch.index! + destructMatch[0].length - 1;
    destructMatch[1].split(",").forEach((v) => {
      const name = v
        .trim()
        .split(/\s*[:=]/)[0]
        .trim();
      if (name) push(name, eqIdx);
    });
  }

  // Python / Ruby: x = ... (line start)
  const pyMatch = line.match(/^(\w+)\s*=(?!=)/);
  if (pyMatch && !line.includes("==")) push(pyMatch[1], pyMatch[0].length - 1);

  // Java/C#/typed languages: `[modifiers] [pkg.Qualified] Type[<G>] name = ...`.
  // Handles fully-qualified types (java.io.File), generics (List<String>) and
  // reassignments where the declared type is omitted (`param = decode(..)`).
  // Uses `=(?!=)` (negative lookahead) instead of `=[^=]` so that multiline
  // declarations ending with `=` at EOL (e.g. `File f =\n  new File(...)`) match.
  for (const m of line.matchAll(
    /(?:^|[;{}\s])(?:final\s+|static\s+|private\s+|public\s+|protected\s+)*(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:<[^<>]*>)?\s+([A-Za-z_$][\w$]*)\s*=(?!=)/g,
  )) {
    push(m[1], m.index! + m[0].length - 1);
  }

  // Bare reassignment of an existing identifier (`param = ...`, `fileName = ...`).
  // Includes += accumulation (`src += 'return ' + code` — CVE-2019-10759).
  for (const m of line.matchAll(/(?:^|[;{}\s])([A-Za-z_$][\w$]*)\s*\+?=(?!=)/g)) {
    push(m[1], m.index! + m[0].length - 1);
  }

  // PHP: $x = ...
  for (const m of line.matchAll(/\$(\w+)\s*=/g))
    push("$" + m[1], m.index! + m[0].length - 1);

  // Go: x := ...
  for (const m of line.matchAll(/(\w+)\s*:=/g))
    push(m[1], m.index! + m[0].length - 2);

  // De-duplicate by name (keep the first assignment position).
  const seen = new Set<string>();
  return out.filter((a) =>
    seen.has(a.name) ? false : (seen.add(a.name), true),
  );
}

/** True when a line opens more parentheses than it closes (a multiline call whose
 * arguments continue on the next line). Used to gate the multiline sink window. */
function hasUnclosedParen(line: string): boolean {
  let depth = 0;
  for (const ch of line) {
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
  }
  return depth > 0;
}

/**
 * True when the RHS of an assignment does NOT genuinely propagate taint — i.e.
 * any tainted variable that appears on the line is *neutralized*:
 *  1. Pure constant RHS (string/number/null literals, no tainted var).
 *  2. Ternary `cond ? A : B` with a provably-constant condition (arithmetic on
 *     literals only) where the tainted variable appears ONLY in the dead branch.
 *     E.g. `(7*18)+num > 200 ? "This_should_always_happen" : param` — condition is
 *     always true (126+106=232>200), so `param` in the false-branch is dead code.
 */
function isNeutralizedRhs(
  rhs: string,
  taintedVars: Map<string, TaintedVar>,
  lines?: string[],
  lineIdx?: number,
): boolean {
  // Strip leading `=` and whitespace (collectAssignments idx points one before `=`).
  const trimmedRhs = rhs
    .replace(/^\s*=\s*/, "")
    .replace(/;\s*$/, "")
    .trim();

  // Empty RHS (multiline assignment: `bar =\n  expr;`) or unclosed paren (call
  // continues on next line) → cannot determine neutrality → assume NOT neutralized.
  if (trimmedRhs === "" || hasUnclosedParen(trimmedRhs)) return false;

  // Quick check: does any tainted var actually appear in the RHS?
  let taintedInRhs = false;
  for (const name of taintedVars.keys()) {
    if (name.startsWith("__inline_")) continue;
    if (identRegex(name).test(trimmedRhs)) {
      taintedInRhs = true;
      break;
    }
  }

  // Numeric coercion: `x = parseInt(x, 10)` / `Number(x)` / `parseFloat(x)`
  // yields a number — shell/SQL/HTML metacharacters cannot survive, so the
  // taint is neutralized regardless of the tainted argument (CVE-2017-16034 fix).
  if (taintedInRhs) {
    const coerced = trimmedRhs.match(
      /^(?:\([^)]*\)\s*)?(?:parseInt|parseFloat|Number|Math\s*\.\s*(?:floor|ceil|round|trunc|abs))\s*\(/,
    );
    if (coerced) return true;
  }
  // No tainted var in the RHS → constant assignment. We do NOT kill taint here
  // because single-pass analysis can't determine order (the constant may precede
  // the tainted reassignment). Dead-branch tracking (dbState.dead) handles the
  // OWASP FALSE cases where the constant is in the LIVE branch and the tainted
  // assignment is in the DEAD branch — those are skipped entirely by Step 2.
  // EXCEPTION: list/collection access with integer index (e.g., `list.get(1)`)
  // is a safe reassignment — the value comes from a specific position, not from
  // a tainted data flow. This handles the OWASP pattern:
  //   valuesList.add(param); bar = valuesList.get(1); // gets "moresafe", not param
  if (!taintedInRhs) {
    if (/\.get\s*\(\s*\d+\s*\)/.test(trimmedRhs)) return true;
    return false;
  }

  // Ternary with a constant condition: `cond ? trueBranch : falseBranch`
  const ternary = splitTernary(trimmedRhs);
  if (ternary) {
    const { condition, trueBranch, falseBranch } = ternary;
    const evalCond = evalConstCondition(condition, lines, lineIdx);
    if (evalCond !== null) {
      // Condition is provably constant. The dead branch is the one NOT taken.
      const deadBranch = evalCond ? falseBranch : trueBranch;
      const liveBranch = evalCond ? trueBranch : falseBranch;
      // Kill if tainted var is ONLY in the dead branch (not in the live one).
      let inLive = false;
      let inDead = false;
      for (const name of taintedVars.keys()) {
        if (name.startsWith("__inline_")) continue;
        const re = identRegex(name);
        if (re.test(liveBranch)) inLive = true;
        if (re.test(deadBranch)) inDead = true;
      }
      if (inDead && !inLive) return true;
    }
  }

  return false;
}

/**
 * Split a ternary expression `cond ? A : B` at the TOP level (respecting nested
 * parens/strings). Returns null if the expression is not a single ternary.
 */
function splitTernary(
  expr: string,
): { condition: string; trueBranch: string; falseBranch: string } | null {
  let depth = 0;
  let qIdx = -1;
  let cIdx = -1;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "?" && depth === 0 && qIdx < 0) {
      qIdx = i;
    } else if (ch === ":" && depth === 0 && qIdx >= 0 && cIdx < 0) {
      cIdx = i;
    }
  }
  if (qIdx < 0 || cIdx < 0) return null;
  return {
    condition: expr.slice(0, qIdx).trim(),
    trueBranch: expr.slice(qIdx + 1, cIdx).trim(),
    falseBranch: expr.slice(cIdx + 1).trim(),
  };
}

/**
 * Evaluate a condition that consists of numeric/arithmetic expressions, possibly
 * referencing local constants assigned on nearby preceding lines (e.g. `int num = 106;`).
 * Returns true/false if the condition is provably constant, or null if it contains
 * unresolvable variables.
 *
 * OWASP always-true ternaries use patterns like `(7*18)+num > 200` where `num` is
 * a local constant. We resolve such variables by scanning back a few lines for a
 * simple numeric assignment.
 */
function evalConstCondition(
  cond: string,
  lines?: string[],
  lineIdx?: number,
): boolean | null {
  let expr = cond;

  // Resolve simple local constant variables (e.g. `int num = 106;`).
  const identifiers = expr.match(/[A-Za-z_$][\w$]*/g);
  if (identifiers && lines && lineIdx !== undefined) {
    for (const ident of identifiers) {
      // Skip common keywords that aren't variables
      if (/^(true|false|null|undefined|NaN|Infinity)$/.test(ident)) continue;
      const val = resolveLocalNumericConst(lines, lineIdx, ident);
      if (val !== null) {
        expr = expr.replace(
          new RegExp(`\\b${escapeRegex(ident)}\\b`, "g"),
          String(val),
        );
      } else {
        return null; // unresolvable variable → cannot evaluate
      }
    }
  } else if (identifiers) {
    return null; // has variables but no lines context to resolve them
  }

  // Now expr should be purely numeric/operators.
  if (/[A-Za-z_$]/.test(expr)) return null;
  try {
    // eslint-disable-next-line no-eval
    const result = eval(expr);
    if (typeof result === "boolean") return result;
    if (typeof result === "number") return result !== 0;
  } catch {
    /* not evaluable */
  }
  return null;
}

/**
 * Scan backwards from `lineIdx` (exclusive) up to 10 lines looking for a simple
 * numeric constant assignment to `varName`, e.g. `int num = 106;` or `num = 80;`.
 * Returns the numeric value or null if not found.
 */
function resolveLocalNumericConst(
  lines: string[],
  lineIdx: number,
  varName: string,
): number | null {
  const re = new RegExp(
    `(?:^|[;{}\\s])(?:final\\s+|static\\s+)*(?:int|long|short|byte|float|double|Integer|Long|Double|Float|Short|Byte)?\\s*${escapeRegex(varName)}\\s*=\\s*(-?[\\d.]+)\\s*[;]`,
  );
  for (let k = lineIdx - 1; k >= Math.max(0, lineIdx - 10); k--) {
    const m = lines[k].match(re);
    if (m) {
      const n = parseFloat(m[1]);
      if (!isNaN(n)) return n;
    }
  }
  return null;
}

/**
 * Resolve a local char/string constant variable by scanning backwards from lineIdx.
 * Handles patterns like: `char switchTarget = guess.charAt(1);` where guess = "ABC"
 * or direct: `char c = 'B';` / `String s = "B";`
 * Returns the resolved character/string value or null.
 */
function resolveLocalCharConst(
  lines: string[],
  lineIdx: number,
  varName: string,
): string | null {
  const re = new RegExp(
    `(?:^|[;{}\\s])(?:final\\s+|static\\s+)*(?:char|String|Character)?\\s*${escapeRegex(varName)}\\s*=\\s*(.+?)\\s*;`,
  );
  for (let k = lineIdx - 1; k >= Math.max(0, lineIdx - 15); k--) {
    const m = lines[k].match(re);
    if (!m) continue;
    const rhs = m[1].trim();
    // Direct char literal: 'B'
    const charLit = rhs.match(/^'([^'])'$/);
    if (charLit) return charLit[1];
    // Direct string literal: "B"
    const strLit = rhs.match(/^"([^"]*)"$/);
    if (strLit) return strLit[1];
    // charAt pattern: someVar.charAt(N)
    const charAtM = rhs.match(
      /^([A-Za-z_$][\w$]*)\s*\.\s*charAt\s*\(\s*(\d+)\s*\)$/,
    );
    if (charAtM) {
      const srcVal = resolveLocalStringConst(lines, k, charAtM[1]);
      if (srcVal !== null) {
        const idx = parseInt(charAtM[2], 10);
        if (idx < srcVal.length) return srcVal[idx];
      }
      return null;
    }
    return null;
  }
  return null;
}

/**
 * Blank out string-literal contents and trailing comments, preserving line
 * length and positions (each masked char becomes a space, quotes are kept).
 * Word-boundary taint matching must run against the masked line: a variable
 * name that only appears inside a string literal (e.g. `"os.name"`,
 * `"Parameter value: "`) or in a comment (e.g. `// get the last 'safe' value`)
 * is NOT a data-flow reference, and treating it as one causes false positives.
 */
function maskNonCode(line: string): string {
  const chars = line.split("");
  let inStr: string | null = null;
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (inStr) {
      if (c === "\\") {
        chars[i] = " ";
        if (i + 1 < chars.length) chars[i + 1] = " ";
        i++;
        continue;
      }
      if (c === inStr) {
        inStr = null;
        continue; // keep the closing quote
      }
      chars[i] = " ";
    } else {
      if (c === '"' || c === "'") {
        inStr = c;
        continue; // keep the opening quote
      }
      if (c === "/" && chars[i + 1] === "/") {
        for (let j = i; j < chars.length; j++) chars[j] = " ";
        break;
      }
    }
  }
  return chars.join("");
}

/**
 * Strip a trailing // comment from a line, respecting string literals.
 * Returns the code-only portion (without the comment).
 */
function stripTrailingComment(line: string): string {
  let inStr: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inStr) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === inStr) inStr = null;
    } else {
      if (c === '"' || c === "'") {
        inStr = c;
        continue;
      }
      if (c === "/" && line[i + 1] === "/") return line.slice(0, i).trimEnd();
    }
  }
  return line;
}

/**
 * Find the index of the first simple assignment operator (=) in a line,
 * excluding ==, !=, <=, >=. Returns -1 if no assignment found.
 */
function findAssignOp(line: string): number {
  const m = line.match(/(?<![=!<>])=(?!=)/);
  return m && m.index !== undefined ? m.index : -1;
}

function findTaintedInLine(
  line: string,
  taintedVars: Map<string, TaintedVar>,
  currentLine: number,
): TaintedVar | null {
  // Mask string literals and comments: a tainted var name inside a string
  // (e.g. `"Parameter value: "`) or comment is not a data-flow reference.
  const masked = maskNonCode(line);
  for (const [varName, tv] of taintedVars) {
    if (varName.startsWith("__inline_")) {
      // Inline source — only valid on the same line
      if (tv.sourceLine === currentLine) return tv;
      continue;
    }
    // Check if the tainted variable appears in the sink line
    const varRegex = identRegex(varName);
    if (varRegex.test(masked)) {
      return tv;
    }
  }
  return null;
}

/**
 * Sink-call argument-span taint check. On a line like
 *   exec(cmd + pid, function (err, stdout, stderr) {
 * a line-wide check matches `stdout`/`stderr` — but those are callback
 * PARAMETERS (declarations), not data flowing into `exec`. For call-style
 * sinks we only consider identifiers inside the sink call's argument span,
 * with inline callback signatures stripped. Non-call sinks (assignment sinks
 * like `.innerHTML =`) fall back to the line-wide check.
 */
function findTaintedInSinkCall(
  line: string,
  sinkRegex: RegExp,
  taintedVars: Map<string, TaintedVar>,
  currentLine: number,
): TaintedVar | null {
  const m = sinkRegex.exec(line);
  if (!m) return null;
  // The sink's argument list opens at the LAST `(` of the match — chained
  // calls match intermediate parens first (`response.status(404).send(…)`).
  const lastParenInMatch = m[0].lastIndexOf("(");
  const paren =
    lastParenInMatch >= 0
      ? m.index + lastParenInMatch
      : line.indexOf("(", m.index);
  if (paren < 0) return findTaintedInLine(line, taintedVars, currentLine); // non-call sink
  let depth = 0;
  let end = line.length;
  for (let k = paren; k < line.length; k++) {
    if (line[k] === "(") depth++;
    else if (line[k] === ")") {
      depth--;
      if (depth === 0) {
        end = k;
        break;
      }
    }
  }
  // Argument span PLUS the tail after it closes: chained receivers make the
  // real argument-bearing call come LATER on the line
  // (`response.getWriter().format(locale, param, obj)` — the sink regex matches
  // getWriter, whose span is empty; the tainted arg sits in format's span).
  // The tail applies ONLY when the span carries no identifiers — with a real
  // argument list (`new RegExp(PARAM.source, 'g')`) the tail is a DIFFERENT
  // statement (`var params = value.match(new RegExp(…)), key = args[1]`).
  const spanStripped = line
    .slice(paren + 1, end)
    .replace(/\bfunction\s*[A-Za-z_$][\w$]*\s*\([^)]*\)/g, "function()")
    .replace(/\([^()]*\)\s*=>/g, "() =>")
    .replace(/\b[A-Za-z_$][\w$]*\s*=>/g, "__cb =>");
  if (/[A-Za-z_$]/.test(spanStripped)) {
    return findTaintedInLine(spanStripped, taintedVars, currentLine);
  }
  const combined = `${spanStripped} ${line.slice(Math.min(end + 1, line.length))}`;
  if (!/[A-Za-z_$]/.test(combined)) {
    // No identifiers at all in span+tail (e.g. `new File(param).delete()`) —
    // fall back to the line-wide check.
    return findTaintedInLine(line, taintedVars, currentLine);
  }
  return findTaintedInLine(combined, taintedVars, currentLine);
}

function calculateConfidence(tv: TaintedVar, sinkLine: number): number {
  // Base confidence for taint tracking
  let confidence = 75;

  // Higher confidence if source and sink are close (data flow is clearer)
  const distance = sinkLine - tv.sourceLine;
  if (distance <= 3) confidence += 15;
  else if (distance <= 10) confidence += 10;
  else if (distance <= 30) confidence += 5;

  // Higher confidence if taint path is short (fewer hops = less chance of FP)
  if (tv.path.length <= 2) confidence += 5;

  return Math.min(confidence, 95);
}

function buildDescription(
  sink: DbTaintSink,
  tv: TaintedVar,
  filePath: string,
  sinkLine: number,
): string {
  return (
    `Taint analysis detected unsanitized data flow: ` +
    `User input from "${tv.source}" (line ${tv.sourceLine}) propagates to ` +
    `${sink.category} sink at line ${sinkLine} in ${filePath}. ` +
    `No sanitizer was found in the data path. ` +
    `CWE: ${sink.cwe} | OWASP: ${sink.owasp2021}`
  );
}

function deduplicateFindings(findings: TaintFinding[]): TaintFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.cwe}:${f.filePath}:${f.lineStart}-${f.lineEnd}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Word-boundary regex for an identifier. `\b` fails next to `$` (a NON-word
 * char in regex terms), making `$`-prefixed variables invisible to every
 * taint check (`$config`, `$zipCmd` — node-lambda CVE-2019-10777, jQuery).
 * Lookarounds treat `$` as a word character.
 */
function identRegex(name: string): RegExp {
  return new RegExp(`(?<![\\w$])${escapeRegex(name)}(?![\\w$])`);
}

/** Same boundaries as identRegex but as an embeddable pattern string. */
function identPat(name: string): string {
  return `(?<![\\w$])${escapeRegex(name)}(?![\\w$])`;
}

// ==================== INTER-PROCEDURAL ANALYSIS (JS/TS) ====================

/**
 * Local function index for same-file inter-procedural taint. Real-world JS
 * vulnerabilities (the bulk of the OpenSSF CVE Benchmark) flow through helper
 * calls: `handler(req){ render(res, req.query.x) }` → `render(res, s){ …sink(s) }`.
 * A single-pass line engine cannot see this — the tainted var never appears on
 * the sink line. Indexing local functions lets us (a) detect sinks inside a
 * callee reached with tainted arguments and (b) decide whether a callee's
 * RETURN value carries taint (killing the FP when it provably doesn't).
 */
export interface LocalFunction {
  name: string;
  params: string[];
  /** 0-based index of the definition line. */
  start: number;
  /** 0-based index of the closing-brace line (=== start for expression arrows). */
  end: number;
  /** For `name = (a) => expr` (no braces): the implicit-return expression. */
  implicitReturn?: string;
}

const JS_FN_KEYWORDS = new Set([
  "if",
  "for",
  "while",
  "switch",
  "catch",
  "return",
  "function",
  "else",
  "do",
  "typeof",
  "new",
]);

/** Parse a parameter list into plain identifiers (drops defaults, types, destructuring). */
function parseFnParams(raw: string): string[] {
  const out: string[] = [];
  for (const part of splitTopLevelArgs(raw)) {
    const p = part.trim();
    if (!p || p.startsWith("{") || p.startsWith("[") || p.startsWith("..."))
      continue;
    const m = p.match(/^([A-Za-z_$][\w$]*)/);
    if (m && !JS_FN_KEYWORDS.has(m[1])) out.push(m[1]);
  }
  return out;
}

/** Index named functions defined in this file (JS/TS). */
export function indexLocalFunctions(lines: string[]): Map<string, LocalFunction> {
  const index = new Map<string, LocalFunction>();
  for (let i = 0; i < lines.length; i++) {
    const masked = maskNonCode(lines[i]);
    let name: string | null = null;
    let paramsRaw = "";
    let implicitReturn: string | undefined;

    let m = masked.match(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)/);
    if (m) {
      name = m[1];
      paramsRaw = m[2];
    } else if (
      (m = masked.match(
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\s*\(([^()]*)\)/,
      ))
    ) {
      name = m[1];
      paramsRaw = m[2];
    } else if (
      (m = masked.match(
        /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=\s*(?:async\s+)?function\s*\(([^()]*)\)/,
      ))
    ) {
      name = m[1].split(".").pop()!;
      paramsRaw = m[2];
    } else if (
      (m = masked.match(
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*(.*)$/,
      ))
    ) {
      name = m[1];
      paramsRaw = m[2] ?? m[3] ?? "";
      if (!m[4].includes("{")) implicitReturn = m[4].replace(/;\s*$/, "");
    } else if (
      (m = masked.match(
        /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*=\s*(?:async\s+)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*(.*)$/,
      ))
    ) {
      name = m[1].split(".").pop()!;
      paramsRaw = m[2] ?? m[3] ?? "";
      if (!m[4].includes("{")) implicitReturn = m[4].replace(/;\s*$/, "");
    } else if (
      (m = masked.match(
        /^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{/,
      ))
    ) {
      // Object/class method shorthand — exclude control-flow keywords.
      if (
        !JS_FN_KEYWORDS.has(m[1]) &&
        !/^\s*(?:if|for|while|switch|catch)\b/.test(masked)
      ) {
        name = m[1];
        paramsRaw = m[2];
      }
    }
    if (!name || JS_FN_KEYWORDS.has(name) || index.has(name)) continue;

    // Brace-match the body from the definition line.
    let end = i;
    if (implicitReturn === undefined) {
      let depth = 0;
      let opened = false;
      for (let k = i; k < lines.length; k++) {
        for (const ch of maskNonCode(lines[k])) {
          if (ch === "{") {
            depth++;
            opened = true;
          } else if (ch === "}") depth--;
        }
        end = k;
        if (opened && depth <= 0) break;
      }
    }
    index.set(name, {
      name,
      params: parseFnParams(paramsRaw),
      start: i,
      end,
      implicitReturn,
    });
  }
  return index;
}

/** Split an argument/parameter list at top-level commas (paren/bracket aware). */
function splitTopLevelArgs(raw: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of raw) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      args.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) args.push(cur);
  return args;
}

/**
 * One-level mini taint propagation inside a callee body, seeded with tainted
 * parameters. Returns whether the callee's return value may carry the taint
 * (used for precision: `x = safeHelper(tainted)` must NOT taint x when the
 * helper provably returns something independent of its parameter).
 */
export function calleeReturnsTaint(
  fn: LocalFunction,
  boundParams: Set<string>,
  lines: string[],
  sanitizers: string[],
  fnIndex?: Map<string, LocalFunction>,
  depth = 0,
): boolean {
  if (boundParams.size === 0) return false;
  if (fn.implicitReturn !== undefined) {
    if (sanitizers.some((s) => fn.implicitReturn!.includes(s))) return false;
    for (const p of boundParams) {
      if (new RegExp(`\b${escapeRegex(p)}\b`).test(fn.implicitReturn))
        return true;
    }
    return false;
  }
  const tainted = new Set(boundParams);
  // Multi-hop: does `expr` call another local function with a tainted argument
  // whose return value is tainted?
  const exprCallsTaintedFn = (expr: string): boolean => {
    if (!fnIndex || depth >= 2) return false;
    for (const cm of expr.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(([^;{}]*)\)/g)) {
      const inner = fnIndex.get(cm[1]);
      if (!inner || inner.name === fn.name) continue;
      const args = splitTopLevelArgs(cm[2]);
      const innerBound = new Set<string>();
      args.forEach((arg, idx) => {
        const param = inner.params[idx];
        if (!param) return;
        for (const t of tainted) {
          if (new RegExp(`\b${escapeRegex(t)}\b`).test(arg)) {
            innerBound.add(param);
            break;
          }
        }
      });
      if (
        innerBound.size > 0 &&
        calleeReturnsTaint(
          inner,
          innerBound,
          lines,
          sanitizers,
          fnIndex,
          depth + 1,
        )
      ) {
        return true;
      }
    }
    return false;
  };
  for (let k = fn.start; k <= fn.end && k < lines.length; k++) {
    const masked = maskNonCode(lines[k]);
    const sanitizedLine = sanitizers.some((s) => lines[k].includes(s));
    // return expr → tainted?
    const ret = masked.match(/\breturn\b\s*(.+?);?\s*$/);
    if (ret && !sanitizedLine) {
      for (const t of tainted) {
        if (new RegExp(`\b${escapeRegex(t)}\b`).test(ret[1])) return true;
      }
      if (exprCallsTaintedFn(ret[1])) return true;
    }
    // Simple assignments: propagate or kill.
    for (const am of masked.matchAll(
      /\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+)/g,
    )) {
      const [, lhs, rhs] = am;
      let rhsTainted = false;
      for (const t of tainted) {
        if (new RegExp(`\b${escapeRegex(t)}\b`).test(rhs)) {
          rhsTainted = true;
          break;
        }
      }
      if (!rhsTainted) rhsTainted = exprCallsTaintedFn(rhs);
      if (rhsTainted && !sanitizedLine) tainted.add(lhs);
      else if (tainted.has(lhs) && !rhsTainted) tainted.delete(lhs);
    }
  }
  return false;
}

/**
 * One-level mini taint propagation inside a callee body, seeded with tainted
 * parameters, looking for a sink reached by the tainted data. Returns the first
 * hit (body line + sink + originating taint) or null.
 */
/**
 * Path-composition sinks (path.join/resolve, CWE-22): three generic gates,
 * all rooted in the semantics of path composition. Returns true → SUPPRESS.
 *   1. COMPOSITION only: ≥2 arguments (base + input). A single-arg call
 *      (`webroot = path.resolve(webroot)`) is normalization.
 *   2. TAINTED TAIL: the tainted var must appear in a NON-FIRST arg.
 *      Traversal means INPUT escaping the base; a tainted base (argv
 *      webroot) is a different threat, flagged by other sinks.
 *   3. FORWARD CONFINEMENT: the canonical fixes join FIRST and verify the
 *      result — `x = path.join(base, t); if (x.indexOf(base)!=0) return;`
 *      (unzipper CVE-2018-1002203) or the Node.js documented idiom
 *      `rel = path.relative(base, x); if (rel.startsWith('..')) return;`
 *      (simplehttpserver CVE-2018-16478).
 */
function isConfinedPathJoin(
  sink: DbTaintSink,
  lines: string[],
  i: number,
  taintedNames: string[],
): boolean {
  if (sink.cwe !== "CWE-22") return false;
  const joinCall = maskNonCode(lines[i]).match(
    /\bpath\s*\.\s*(?:join|resolve)\s*\(([^)]*)\)/,
  );
  if (!joinCall) return false;
  const parts = joinCall[1].split(",");
  if (parts.length < 2) return true; // normalization, not composition
  const tail = parts.slice(1).join(",");
  const taintedInTail = taintedNames.some((v) =>
    identRegex(v).test(tail),
  );
  if (!taintedInTail) return true; // tainted base ≠ traversal
  let confined = false;
  const asg = maskNonCode(lines[i]).match(
    /\b([A-Za-z_$][\w$]*)\s*=\s*path\s*\.\s*(?:join|resolve)\s*\(/,
  );
  if (asg) {
    const confRe = new RegExp(
      `\\bif\\s*\\([^)]*\\b${escapeRegex(asg[1])}\\s*\\.\\s*(?:indexOf|startsWith)\\s*\\(`,
    );
    for (let k = 1; k <= 6 && i + k < lines.length && !confined; k++) {
      if (!confRe.test(maskNonCode(lines[i + k]))) continue;
      const window = lines
        .slice(i + k, Math.min(i + k + 4, lines.length))
        .map((line) => maskNonCode(line))
        .join("\n");
      confined = /\b(return|throw|continue|break)\b/.test(window);
    }
  }
  if (!confined) {
    for (let k = 1; k <= 6 && i + k < lines.length && !confined; k++) {
      const rel = maskNonCode(lines[i + k]).match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*path\s*\.\s*relative\s*\(/,
      );
      if (!rel) continue;
      const relRe = new RegExp(
        `\\bif\\s*\\([^)]*\\b${escapeRegex(rel[1])}\\s*\\.\\s*(?:startsWith|indexOf)\\s*\\(`,
      );
      for (let m = 1; m <= 4 && i + k + m < lines.length; m++) {
        if (!relRe.test(maskNonCode(lines[i + k + m]))) continue;
        const window = lines
          .slice(i + k + m, Math.min(i + k + m + 4, lines.length))
          .map(maskNonCode)
          .join("\n");
        confined = /\b(return|throw|continue|break)\b/.test(window);
        break;
      }
    }
  }
  return confined;
}

/**
 * Path guards for the inter-procedural pass — same idioms as the main
 * propagation (`computeTaintedVarNames`): an early-exit `..`-escape check
 * (string-literal or regex-literal) or a base-confinement check untaints the
 * variables in its condition for the rest of the callee body.
 */
function applyPathGuards(
  lines: string[],
  i: number,
  line: string,
  tainted: Map<string, TaintedVar>,
): void {
  // Only the '..' REJECTION guard applies here. The base-confinement idiom
  // (`x.indexOf(base) !== 0 → exit`) is deliberately NOT applied inside
  // callees: a bare prefix check on an unresolved string still lets the
  // suffix carry '../' or HTML payloads (URL vpath prefixes), and the main
  // propagation — where the idiom was tuned — owns it.
  const guard =
    line.match(
      /\bif\s*\(.+(?:indexOf|includes|startsWith|contains)\s*\(\s*['"]\/?\.\.\/?['"]/,
    ) ??
    line.match(
      /\bif\s*\(.+\.(?:match|test|search)\s*\(\s*\/(?:[^/\\]|\\.)*(?:\\?\.){2}(?:[^/\\]|\\.)*\//,
    );
  if (!guard) return;
  let exits = /\b(return|throw|continue|break)\b/.test(
    line.slice(line.indexOf(guard[0]) + guard[0].length),
  );
  if (!exits) {
    let depth = 0;
    for (const ch of line) {
      if (ch === "{") depth++;
      else if (ch === "}") depth--;
    }
    for (let k = 1; k <= 6 && i + k < lines.length && depth > 0; k++) {
      const ahead = maskNonCode(lines[i + k]);
      if (/\b(return|throw|continue|break)\b/.test(ahead)) {
        exits = true;
        break;
      }
      for (const ch of ahead) {
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
      }
    }
  }
  if (!exits) return;
  const cond = line.slice(line.indexOf(guard[0]));
  for (const name of [...tainted.keys()]) {
    if (name.startsWith("__inline_")) continue;
    if (identRegex(name).test(cond))
      tainted.delete(name);
  }
}

function calleeSinkHit(
  fn: LocalFunction,
  boundParams: Map<string, TaintedVar>,
  compiledSinks: { sink: DbTaintSink; regex: RegExp }[],
  sanitizers: string[],
  lines: string[],
  fnIndex?: Map<string, LocalFunction>,
  depth = 0,
): { line: number; sink: DbTaintSink; tv: TaintedVar } | null {
  if (boundParams.size === 0 || fn.implicitReturn !== undefined) return null;
  const tainted = new Map(boundParams);
  for (let k = fn.start; k <= fn.end && k < lines.length; k++) {
    const line = lines[k];
    const masked = maskNonCode(line);
    for (const { sink, regex } of compiledSinks) {
      if (!regex.test(line)) continue;
      if (isConfinedPathJoin(sink, lines, k, [...tainted.keys()])) continue;
      const hit = findTaintedInSinkCall(line, regex, tainted, k + 1);
      if (!hit) continue;
      // Same sink-level gate as the main loop: string coercion kills NoSQL
      // operator injection (CWE-89).
      if (sink.cwe === "CWE-89") {
        const v = escapeRegex(hit.name);
        if (
          new RegExp(`\\$\\{\\s*${v}\\s*\\}`).test(line) ||
          new RegExp(`\\b${v}\\s*\\.\\s*toString\\s*\\(`).test(line)
        )
          continue;
      }
      const sanitizerOnLine = sanitizers.some((s) => line.includes(s));
      const sanitizerInPath = hit.path.some((p) =>
        sanitizers.some((s) => p.includes(s)),
      );
      if (!sanitizerOnLine && !sanitizerInPath)
        return { line: k + 1, sink, tv: hit };
    }
    // Path guards (escape/confinement) apply inside callees exactly as in the
    // main propagation — a guarded var is inert for the rest of the body.
    applyPathGuards(lines, k, line, tainted);
    // Multi-hop: the callee passes tainted data to ANOTHER local function —
    // follow it (bounded depth to stay fast and non-re-entrant).
    if (fnIndex && depth < 2) {
      const callRe = /\b([A-Za-z_$][\w$]*)\s*\(([^;{}]*)\)/g;
      let cm: RegExpExecArray | null;
      while ((cm = callRe.exec(masked)) !== null) {
        const inner = fnIndex.get(cm[1]);
        if (!inner || inner.name === fn.name) continue;
        if (k >= inner.start && k <= inner.end) continue; // definition site / recursion
        const args = splitTopLevelArgs(cm[2]);
        const innerBound = new Map<string, TaintedVar>();
        args.forEach((arg, idx) => {
          const param = inner.params[idx];
          if (!param) return;
          for (const [, tv] of tainted) {
            if (tv.name.startsWith("__inline_")) continue;
            if (identRegex(tv.name).test(arg)) {
              innerBound.set(param, {
                name: param,
                sourceLine: tv.sourceLine,
                source: tv.source,
                path: [
                  ...tv.path,
                  `${inner.name}(${param} ⇐ tainted arg) (line ${k + 1})`,
                ],
              });
              break;
            }
          }
        });
        if (innerBound.size === 0) continue;
        const hit = calleeSinkHit(
          inner,
          innerBound,
          compiledSinks,
          sanitizers,
          lines,
          fnIndex,
          depth + 1,
        );
        if (hit) return hit;
      }
    }
    // Propagate/kill on simple assignments (same approximation as the main pass).
    const sanitizedLine = sanitizers.some((s) => line.includes(s));
    for (const am of masked.matchAll(
      /\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+)/g,
    )) {
      const [, lhs, rhs] = am;
      let rhsTv: TaintedVar | null = null;
      for (const [, tv] of tainted) {
        if (tv.name.startsWith("__inline_")) continue;
        if (identRegex(tv.name).test(rhs)) {
          rhsTv = tv;
          break;
        }
      }
      if (rhsTv && !sanitizedLine && !tainted.has(lhs)) {
        tainted.set(lhs, {
          name: lhs,
          sourceLine: rhsTv.sourceLine,
          source: rhsTv.source,
          path: [...rhsTv.path, `${lhs} = … (line ${k + 1}, in ${fn.name})`],
        });
      } else if (!rhsTv && tainted.has(lhs)) {
        tainted.delete(lhs);
      }
    }
  }
  return null;
}

// ==================== EXPORTED-FUNCTION PARAMETER SOURCES (JS/TS) ====================

/** Event names whose handler callbacks receive attacker-controlled data. */
const JS_DATA_EVENTS = new Set([
  "data",
  "message",
  "request",
  "text",
  "packet",
  "frame",
  "connection",
  "connect",
  "upgrade",
  "response",
  // Archive extraction streams deliver attacker-controlled entries (Zip-Slip):
  // `unzipper.on('entry', entry => …)` — CVE-2018-1002203.
  "entry",
]);

/**
 * Event-emitter handler parameters as taint sources (JS/TS): network streams
 * deliver attacker data via `.on("data", buf => …)` / `.on("message", fn)`.
 * Only DATA-carrying events qualify — lifecycle events (close/error/drain) do
 * not carry a payload.
 */
function findEventHandlerParams(
  lines: string[],
  skipEvents?: Set<string>,
): { name: string; line: number }[] {
  const out: { name: string; line: number }[] = [];
  const seen = new Set<string>();
  const fnRe =
    /\.on\(\s*['"]([a-zA-Z]+)['"]\s*,\s*(?:async\s+)?(?:function(?:\s+[A-Za-z_$][\w$]*)?\s*)?\(\s*([A-Za-z_$][\w$]*)/;
  const arrowRe =
    /\.on\(\s*['"]([a-zA-Z]+)['"]\s*,\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/;
  for (let i = 0; i < lines.length; i++) {
    // Process OUTPUT streams are not attacker input: `proc.stdout.on('data')`
    // delivers the child process's own output, not network data.
    if (/\.\s*(?:stdout|stderr)\s*\.\s*on\s*\(/.test(lines[i])) continue;
    // NOTE: raw line, NOT maskNonCode — the event name is a string literal
    // (`.on('data', …)`) that masking would blank out.
    const m = lines[i].match(fnRe);
    const evt = m?.[1] ?? lines[i].match(arrowRe)?.[1];
    const param = m?.[2] ?? lines[i].match(arrowRe)?.[2];
    if (!evt || !param || !JS_DATA_EVENTS.has(evt.toLowerCase())) continue;
    if (skipEvents?.has(evt.toLowerCase())) continue;
    if (
      JS_CALLBACK_PARAMS.has(param) ||
      JS_ENV_GLOBALS.has(param) ||
      seen.has(param)
    )
      continue;
    seen.add(param);
    out.push({ name: param, line: i + 1 });
  }
  return out;
}

/** Parameter names that are conventionally callbacks, not attacker data. */
const JS_CALLBACK_PARAMS = new Set([
  "cb",
  "callback",
  "next",
  "done",
  "fn",
  "resolve",
  "reject",
  "then",
  "err",
  "error",
]);

/**
 * Host-environment globals that must never be seeded as tainted, even when a
 * function parameter shadows them (e.g. `_sanitize = function (document, node)`
 * in html-janitor, where `document` is an *inert* document). Treating the global
 * `document`/`window`/… objects as attacker input taints the whole file.
 */
const JS_ENV_GLOBALS = new Set([
  "document",
  "window",
  "global",
  "globalThis",
  "self",
  "process",
  "module",
  "exports",
  "require",
  "console",
  "navigator",
  "location",
  "history",
  "this",
]);

/**
 * Identify parameters of a module's PUBLIC API functions (JS/TS) so they can be
 * seeded as taint sources — for a library, the trust boundary is its exported
 * surface. Recognized shapes:
 *   exports.foo = function (a, b) {…}      module.exports = function (a, b) {…}
 *   foo = exports.foo = function foo(a, b) {…}   export function foo(a, b) {…}
 *   export const foo = (a, b) => …         module.exports.foo = async (a, b) => …
 * Callback-convention names (cb, next, done, …) are excluded: they are invoked
 * BY the library, not supplied by the attacker.
 */
export function findExportedFunctionParams(
  lines: string[],
): { name: string; line: number }[] {
  const out: { name: string; line: number }[] = [];
  const seen = new Set<string>();

  const pushParams = (
    raw: string,
    lineNum: number,
    allowDestructured = true,
    skipDomNames = false,
  ) => {
    // DOM-ish names in CLASS methods are conventionally DOM objects (bootstrap's
    // `handle(event)`, `triggerTransitionEnd(element)`), not attacker strings —
    // seeding them floods jQuery sinks with FPs (CVE-2016-10735 regression).
    const DOM_NAMES = new Set([
      "event", "e", "ev", "evt", "element", "el", "target", "node", "dom",
    ]);
    for (let p of raw.split(",")) {
      p = p.trim();
      // Destructured object params (`{ renderPage }`) of exported CLASS methods
      // are framework-supplied lifecycle objects (Next.js et al.), not attacker
      // input — the class-seeding path passes allowDestructured=false.
      if (!allowDestructured && /^[{[]/.test(p)) continue;
      // Strip JSDoc type comments (`/*String*/path` — adm-zip), default values,
      // TS type annotations, and destructuring braces.
      p = p
        .replace(/\/\*[^*]*\*\//g, "")
        .replace(/=.*$/, "")
        .replace(/\?\s*(?=:)/, "")
        .replace(/:\s*[^,]*$/, "")
        .replace(/[{}[\]]/g, "")
        .trim();
      if (
        /^[A-Za-z_$][\w$]*$/.test(p) &&
        p !== "$" &&
        p !== "_" &&
        !JS_CALLBACK_PARAMS.has(p) &&
        !JS_ENV_GLOBALS.has(p) &&
        !(skipDomNames && DOM_NAMES.has(p)) &&
        !seen.has(p)
      ) {
        seen.add(p);
        out.push({ name: p, line: lineNum });
        if (process.env.SEED_DEBUG)
          console.error(`PUSH ${p}@${lineNum} ad=${allowDestructured} dom=${skipDomNames}`);
      }
    }
  };

  const patterns = [
    // exports.foo = function foo(a, b)  |  module.exports = function (a, b)
    // (also covers the chained form `foo = exports.foo = function foo(a, b)`)
    /(?:module\s*\.\s*)?exports(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*=\s*(?:async\s+)?function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/,
    // exports.foo = (a, b) =>  |  module.exports.foo = async (a, b) =>
    /(?:module\s*\.\s*)?exports(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
    // export function foo(a, b)  |  export default function (a, b)
    /\bexport\s+(?:default\s+)?(?:async\s+)?function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/,
    // export const foo = (a, b) =>
    /\bexport\s+const\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
    // Foo.prototype.bar = function (a, b) — prototype methods are public API.
    /\b[A-Za-z_$][\w$]*\s*\.\s*prototype\s*\.\s*[A-Za-z_$][\w$]*\s*=\s*(?:async\s+)?function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/,
    /\b[A-Za-z_$][\w$]*\s*\.\s*prototype\s*\.\s*[A-Za-z_$][\w$]*\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
  ];

  // `module.exports = foo;` / `exports = module.exports = foo;` — the exported
  // value is a named function declared elsewhere in the file. Collected in a
  // FIRST pass: the export statement commonly sits at the END of the file while
  // the object/function it names is declared at the TOP (CVE-2017-16034).
  const exportedNames = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const masked = maskNonCode(lines[i]);
    const nameMatch = masked.match(
      /(?:exports\s*=\s*)?module\s*\.\s*exports\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/,
    );
    if (nameMatch) exportedNames.add(nameMatch[1]);
    // `export default Readme;` — the component/function is declared separately
    // (React arrow components: `const Readme = (props) => …; export default …`).
    const defaultMatch = masked.match(
      /\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*;?\s*$/,
    );
    if (defaultMatch) exportedNames.add(defaultMatch[1]);
    // HOC wrappers: `export default memo(PreviewWysiwyg)` / `connect()(Comp)` —
    // the exported value is the INNER component's params.
    const wrapperMatch = masked.match(
      /\bexport\s+default\s+[A-Za-z_$][\w$]*(?:\([^)]*\))*\(\s*([A-Za-z_$][\w$]*)\s*\)/,
    );
    if (wrapperMatch) exportedNames.add(wrapperMatch[1]);
  }
  // True when the module exports an OBJECT LITERAL (`module.exports = { … }` or
  // `var stats = { … }; module.exports = stats;`): every `key: function (…)` /
  // shorthand `key(…) {` inside is public API.
  let objectLiteralExport = false;
  for (let i = 0; i < lines.length; i++) {
    const masked = maskNonCode(lines[i]);
    if (/module\s*\.\s*exports\s*=\s*\{/.test(masked)) objectLiteralExport = true;
    // Namespace-assigned object literals (`self.accessibility.liveRegion = {`,
    // `$.fn.tooltip = {`) are plugin API surfaces — their methods' params are
    // attacker-controllable. Plain identifiers (`Util = {`) are excluded:
    // internal helper objects would over-taint framework files.
    if (/\b[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)+\s*=\s*\{/.test(masked)) {
      objectLiteralExport = true;
      if (process.env.SEED_DEBUG) console.error(`OBJLIT-NS L${i + 1}: ${masked.trim().slice(0, 70)}`);
    }
    // CommonJS IIFE export: `module.exports = (function () { … return { … }; })()`
    // — the returned object literal is the module's public API (adm-zip's
    // Utils — CVE-2018-1002204). ESM `export default` IIFEs are NOT matched
    // (bootstrap's Util regression class stays excluded).
    if (/module\s*\.\s*exports\s*=\s*\(\s*function\s*\(\s*\)\s*\{/.test(masked)) objectLiteralExport = true;
    if (exportedNames.size > 0) {
      const objAssign = masked.match(
        /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\{/,
      );
      if (objAssign && exportedNames.has(objAssign[1]))
        objectLiteralExport = true;
    }
  }

  for (let i = 0; i < lines.length; i++) {
    let masked = maskNonCode(lines[i]);
    // Multi-line signatures: `export function renderJsDashboard(\n
    //   packagesPath: any,\n  dashboardName: any,\n)` — join lines until the
    // parameter list closes so the per-line regexes can see the whole list.
    const openCount = (masked.match(/\(/g) ?? []).length;
    const closeCount = (masked.match(/\)/g) ?? []).length;
    if (openCount > closeCount && /(?:function|=>|=|\bexport\b)\s*[A-Za-z_$\w$]*\s*\(/.test(masked)) {
      let joined = masked;
      for (let k = i + 1; k < Math.min(lines.length, i + 9); k++) {
        joined += " " + maskNonCode(lines[k]).trim();
        if ((joined.match(/\)/g) ?? []).length >= openCount) break;
      }
      masked = joined;
    }
    for (const re of patterns) {
      const m = masked.match(re);
      if (m) {
        pushParams(m[1], i + 1);
        break;
      }
    }
    // Named exported function declaration: `function foo(a, b) {` for exported `foo`.
    if (exportedNames.size > 0) {
      const fnDecl = masked.match(
        /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/,
      );
      if (fnDecl && exportedNames.has(fnDecl[1])) pushParams(fnDecl[2], i + 1);
      // Exported arrow function: `const Readme = (props) => …` — and the
      // single-param paren-less form `const f = x => …`.
      const arrowDecl = masked.match(
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
      );
      if (arrowDecl && exportedNames.has(arrowDecl[1]))
        pushParams(arrowDecl[2], i + 1);
      const arrowBare = masked.match(
        /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/,
      );
      if (arrowBare && exportedNames.has(arrowBare[1]))
        pushParams(arrowBare[2], i + 1);
    }
    // Object-literal export members: `key: function (a, b)` or shorthand `key(a, b) {`.
    if (objectLiteralExport) {
      const memberFn = masked.match(
        /\b[A-Za-z_$][\w$]*\s*:\s*(?:async\s+)?function\s*[A-Za-z_$\w$]*\s*\(([^)]*)\)/,
      );
      // DOM-ish param names are excluded here too: the object-literal gate can
      // be opened by ANY exported name in the file (bootstrap's
      // `export default Util;` + IIFE return objects), and framework object
      // methods take DOM events/elements, not attacker strings.
      if (memberFn) pushParams(memberFn[1], i + 1, true, true);
      else {
        const shorthand = masked.match(
          /^\s*(?:async\s+)?(?!function\b)[A-Za-z_$][\w$]*\s*\(([^()]*)\)\s*\{\s*$/,
        );
        if (shorthand) pushParams(shorthand[1], i + 1, true, true);
        else {
          // Arrow members: `suggestion: (match: Match) => …` (typeahead's
          // XSS — CVE-2018-14380) and the paren-less form `key: x => …`.
          const memberArrow = masked.match(
            /\b[A-Za-z_$][\w$]*\s*:\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
          );
          if (memberArrow) pushParams(memberArrow[1], i + 1, true, true);
          else {
            const memberArrowBare = masked.match(
              /\b[A-Za-z_$][\w$]*\s*:\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/,
            );
            if (memberArrowBare) pushParams(memberArrowBare[1], i + 1, true, true);
          }
        }
      }
    }
  }

  // Exported classes: `module.exports = class …` / `export (default )?class …`
  // — and INSTANCE exports (`module.exports = new Foo;`), where the class
  // declaration sits elsewhere in the file (libnmap's `new tools`).
  // Their constructor and methods ARE the public API surface — every method
  // parameter crosses the trust boundary (class-based libraries).
  const instanceExported = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const im = maskNonCode(lines[i]).match(
      /\bmodule\s*\.\s*exports(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*[;(]/,
    );
    if (im) instanceExported.add(im[1]);
  }
  // Instance-exported CONSTRUCTOR FUNCTIONS (`var Lambda = function (o) {…};
// module.exports = new Lambda()` — node-lambda CVE-2019-10777): the
  // constructor's params become instance state (`this.settings = o`) read by
  // prototype methods — seed them.
  if (instanceExported.size > 0) {
    for (let i = 0; i < lines.length; i++) {
      const masked = maskNonCode(lines[i]);
      for (const name of instanceExported) {
        const ctor = masked.match(
          new RegExp(
            `\\bfunction\\s+${escapeRegex(name)}\\s*\\(([^)]*)\\)|\\b(?:var|let|const)\\s+${escapeRegex(name)}\\s*=\\s*function\\s*\\(([^)]*)\\)`,
          ),
        );
        if (ctor) pushParams(ctor[1] ?? ctor[2] ?? "", i + 1, false, true);
      }
    }
  }
  for (let i = 0; i < lines.length; i++) {
    const masked = maskNonCode(lines[i]);
    const directExport =
      /(?:module\s*\.\s*exports(?:\s*\.\s*[A-Za-z_$][\w$]*)?\s*=|\bexport\s+(?:default\s+)?)\s*(?:abstract\s+)?class\b/.test(
        masked,
      );
    const instanceExport =
      instanceExported.size > 0 &&
      [...instanceExported].some((name) =>
        new RegExp(`\\bclass\\s+${name}\\b`).test(masked),
      );
    // Plugin/lifecycle contract: `class X extends Base` — the base class calls
    // these methods with external data (Cyclone's `class … extends Operation`,
    // CVE-2019-15532). DOM-ish param names are excluded by the caller.
    const extendsClass = /\bclass\s+[A-Za-z_$][\w$]*\s+extends\s+[A-Za-z_$]/.test(
      masked,
    );
    if (!directExport && !instanceExport && !extendsClass) continue;
    // Brace-match the class body.
    let depth = 0;
    let opened = false;
    let end = i;
    for (let k = i; k < lines.length; k++) {
      for (const ch of maskNonCode(lines[k])) {
        if (ch === "{") {
          depth++;
          opened = true;
        } else if (ch === "}") depth--;
      }
      end = k;
      if (opened && depth <= 0) break;
    }
    for (let k = i; k <= end; k++) {
      const body = maskNonCode(lines[k]);
      // Method declaration: `constructor(opts) {`, `method(a, b) {`, also with
      // single-line bodies (`m(x) { this.x = x; }`) and TS return types. The
      // trailing `{` distinguishes declarations from mere calls.
      const method = body.match(
        /^\s*(?:static\s+|async\s+|get\s+|set\s+)*(?:constructor|[A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?::\s*[A-Za-z_$][\w$[\]<>| ]*)?\s*\{/,
      );
      if (
        method &&
        !/^\s*(?:if|for|while|switch|catch|function)\b/.test(body)
      ) {
        pushParams(method[1], k + 1, false, true);
      }
    }
    break; // one exported class per module is the norm
  }
  return out;
}

/**
 * Identify parameters of HTTP route handlers (JS/TS): functions whose first two
 * parameters are request/response pairs — `function (request, response, details)`,
 * `(req, res) => …`, `app.get('/', function (req, res) {…})`. The request object
 * and any route-capture/extra params (3rd onward, e.g. `details` in beeline) are
 * remote input; the response object (2nd) is NOT (it is the writer, not input).
 */
function findRouteHandlerParams(
  lines: string[],
): { name: string; line: number }[] {
  const out: { name: string; line: number }[] = [];
  const seen = new Set<string>();
  const handlerRe = /\(\s*(request|req)\s*,\s*(response|res)\s*([^)]*)\)/;
  for (let i = 0; i < lines.length; i++) {
    const masked = maskNonCode(lines[i]);
    // Only treat as a handler when the pair appears in a function/arrow signature.
    if (!/function\b|=>\s*\{?$/.test(masked) && !masked.includes("=>")) {
      if (!/\bfunction\b/.test(masked)) continue;
    }
    const m = masked.match(handlerRe);
    if (!m) continue;
    const params = [m[1], ...(m[3] ? m[3].split(",") : [])];
    for (let p of params) {
      p = p
        .trim()
        .replace(/=.*$/, "")
        .replace(/\?\s*(?=:)/, "")
        .replace(/:\s*[^,]*$/, "")
        .replace(/[{}[\]]/g, "")
        .trim();
      if (!/^[A-Za-z_$][\w$]*$/.test(p)) continue;
      if (JS_CALLBACK_PARAMS.has(p) || JS_ENV_GLOBALS.has(p) || seen.has(p))
        continue;
      seen.add(p);
      out.push({ name: p, line: i + 1 });
    }
  }
  return out;
}

// ==================== INNER-CLASS METHOD ANALYSIS ====================

/**
 * Pre-scan the file for inner-class methods (like OWASP's `doSomething`) that do NOT
 * propagate taint from their String parameter to the return value. In the Benchmark's
 * FALSE cases, the method overwrites the parameter-derived variable with a constant
 * before returning. Detecting this eliminates ~98% of remaining false positives.
 *
 * Returns a Set of method names that are "safe" (neutralize taint).
 */
function findSafeInnerMethods(
  lines: string[],
  sanitizers: string[],
): { safeMethods: Set<string>; safeRanges: [number, number][] } {
  const safe = new Set<string>();
  const ranges: [number, number][] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(
      /(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?String\s+(\w+)\s*\(\s*HttpServletRequest\s+\w+\s*,\s*String\s+(\w+)\s*\)/,
    );
    if (!m) continue;
    const [, methodName, paramName] = m;
    // Find method body. Two styles:
    //  A) Brace on signature line or standalone `{` on next line → brace-match.
    //  B) OWASP Benchmark style: no method-level braces (signature + throws only).
    //     Detect by checking that the first `{` found is NOT a standalone line.
    let bodyStart = -1;
    let bodyEnd = -1;
    let depth = 0;

    // Check signature line for `{`
    if (lines[i].includes("{")) {
      bodyStart = i;
      for (const ch of lines[i]) {
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
      }
    } else {
      // Check next 1-2 lines for a STANDALONE `{` (method body opener).
      for (let k = i + 1; k <= Math.min(i + 2, lines.length - 1); k++) {
        const t = lines[k].trim();
        if (t === "{" || t.endsWith("{")) {
          // Only treat as method body if it's standalone or ends the line.
          // Skip lines like `if (...) {` which are inner blocks.
          if (t === "{" || /^\{/.test(t)) {
            bodyStart = k;
            break;
          }
          // `throws ... {` or `) {` patterns
          if (!/^(if|for|while|switch|try|catch|else)\b/.test(t)) {
            bodyStart = k;
            break;
          }
        }
      }
    }

    if (bodyStart >= 0) {
      // Brace-style: count from bodyStart, find matching close.
      if (depth === 0) {
        for (const ch of lines[bodyStart]) {
          if (ch === "{") depth++;
          else if (ch === "}") depth--;
        }
      }
      for (let k = bodyStart + 1; k < lines.length && depth > 0; k++) {
        for (const ch of lines[k]) {
          if (ch === "{") depth++;
          else if (ch === "}") depth--;
        }
        if (depth === 0) {
          bodyEnd = k;
          break;
        }
      }
    } else {
      // Brace-less method (OWASP style). Scan forward for `return var;` then
      // the method ends at the next line starting with `}`.
      bodyStart = i;
      for (let k = i + 1; k < lines.length; k++) {
        if (lines[k].match(/return\s+[A-Za-z_$][\w$]*\s*;/)) {
          for (let j = k + 1; j < lines.length; j++) {
            if (lines[j].trim().startsWith("}")) {
              bodyEnd = j;
              break;
            }
          }
          break;
        }
      }
    }
    if (bodyEnd < 0) continue;
    // Find the return statement.
    let returnVar: string | null = null;
    for (let k = bodyEnd; k >= bodyStart; k--) {
      const rm = lines[k].match(/return\s+([A-Za-z_$][\w$]*)\s*;/);
      if (rm) {
        returnVar = rm[1];
        break;
      }
    }
    if (!returnVar) continue;

    // Use dead-branch tracking within the method body to only consider
    // assignments that actually EXECUTE (handles switch on constant target,
    // if/else with constant condition, ternary in dead branch, etc.).
    const bodyLines = lines.slice(bodyStart + 1, bodyEnd);
    const dbStateInner: DeadBranchState = {
      dead: false,
      kind: "none",
      switchValue: null,
      caseLive: false,
      braceDepth: 0,
    };
    const liveLines: { text: string; idx: number }[] = [];
    for (let k = 0; k < bodyLines.length; k++) {
      const trimmed = bodyLines[k].trim();
      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("/*")
      )
        continue;
      updateDeadBranch(dbStateInner, trimmed, bodyLines, k);
      if (
        !dbStateInner.dead &&
        !isInDeadSingleLineElse(bodyLines[k], 0, bodyLines, k)
      ) {
        liveLines.push({ text: trimmed, idx: k });
      }
    }

    // Track taint of the return variable through ONLY live lines.
    // Also track HashMap keys and StringBuilders that contain param.
    let varTainted = false;
    const paramRe = identRegex(paramName);
    const taintedMapKeysInner = new Set<string>(); // e.g., "map95803[keyB-95803]"
    const taintedStringBuilders = new Set<string>(); // e.g., "sbxyz75528"
    // Pre-scan: find map.put("key", param) and new StringBuilder(param) patterns.
    for (const { text: l } of liveLines) {
      const putM = l.match(
        /\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\(\s*"([^"]+)"\s*,/,
      );
      if (putM && paramRe.test(l)) {
        taintedMapKeysInner.add(`${putM[1]}[${putM[2]}]`);
      }
      // StringBuilder created with param: `new StringBuilder(param)` or `StringBuilder sb = new StringBuilder(param)`
      const sbM = l.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*new\s+StringBuilder\s*\(/,
      );
      if (sbM && paramRe.test(l)) {
        taintedStringBuilders.add(sbM[1]);
      }
      // Also: `StringBuilder sb = new StringBuilder(); sb.append(param);`
      const sbDeclM = l.match(
        /\b([A-Za-z_$][\w$]*)\s*=\s*new\s+StringBuilder\s*\(\s*\)/,
      );
      if (sbDeclM) {
        // Check if param is appended to this StringBuilder in any live line
        for (const { text: l2 } of liveLines) {
          if (
            l2.includes(sbDeclM[1]) &&
            /\.append\s*\(/.test(l2) &&
            paramRe.test(l2)
          ) {
            taintedStringBuilders.add(sbDeclM[1]);
            break;
          }
        }
      }
    }
    for (let liIdx = 0; liIdx < liveLines.length; liIdx++) {
      const { text: l, idx: lineIdx } = liveLines[liIdx];
      // Check if this line assigns to the return variable.
      const assignRe = new RegExp(
        `(?:^|[;{}\\s])${escapeRegex(returnVar)}\\s*=(?!=)`,
      );
      const am = l.match(assignRe);
      if (!am) continue;
      let rhs = l.slice(l.indexOf("=") + 1);
      // Multiline lookahead: if the RHS is empty or has unclosed parens, gather
      // subsequent live lines until the expression closes (handles Base64 chains).
      const rhsTrimmedInner = rhs
        .replace(/^\s*=\s*/, "")
        .replace(/;\s*$/, "")
        .trim();
      if (rhsTrimmedInner === "" || hasUnclosedParen(rhsTrimmedInner)) {
        for (let k = liIdx + 1; k < liveLines.length && k <= liIdx + 8; k++) {
          rhs += " " + liveLines[k].text;
          if (!hasUnclosedParen(rhs)) break;
        }
      }
      if (paramRe.test(rhs)) {
        // Check if the RHS applies a known sanitizer to param (e.g. htmlEscape).
        if (sanitizers.some((s) => l.includes(s))) {
          if (varTainted) varTainted = false;
          continue;
        }
        // Check if this is a ternary with a constant condition where param is
        // only in the DEAD branch (e.g., `bar = const_cond ? "safe" : param`).
        const rhsClean = rhs.replace(/;\s*$/, "").trim();
        const ternary = splitTernary(rhsClean);
        if (ternary) {
          const evalCond = evalConstCondition(
            ternary.condition,
            bodyLines,
            lineIdx,
          );
          if (evalCond !== null) {
            const liveBranch = evalCond
              ? ternary.trueBranch
              : ternary.falseBranch;
            const deadBranch = evalCond
              ? ternary.falseBranch
              : ternary.trueBranch;
            if (paramRe.test(deadBranch) && !paramRe.test(liveBranch)) {
              // Param only in dead branch → constant assignment, NOT tainted.
              if (varTainted) varTainted = false;
              continue;
            }
          }
        }
        varTainted = true;
      } else {
        // RHS doesn't reference param directly.
        // Check if it's a map.get("key") where the key was tainted by param.
        const getM = rhs.match(
          /\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*"([^"]+)"\s*\)/,
        );
        if (getM && taintedMapKeysInner.has(`${getM[1]}[${getM[2]}]`)) {
          varTainted = true;
          continue;
        }
        // Check if it's a tainted StringBuilder's .toString() or .append(...).toString()
        const sbToStringM = rhs.match(
          /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:append\s*\([^)]*\)\s*\.\s*)?toString\s*\(/,
        );
        if (sbToStringM && taintedStringBuilders.has(sbToStringM[1])) {
          varTainted = true;
          continue;
        }
        if (varTainted) {
          // Reassigned from non-param source. Check if it's provably constant
          // (string literal, map.get with NON-tainted key, etc.) → kills taint.
          const rhsClean = rhs.replace(/;\s*$/, "").trim();
          if (
            /^"[^"]*"$/.test(rhsClean) ||
            /^'[^']*'$/.test(rhsClean) ||
            /^-?[\d.]+$/.test(rhsClean)
          ) {
            varTainted = false;
          } else if (/\.get\s*\(\s*"[^"]*"\s*\)/.test(rhsClean) && !getM) {
            // .get() with a key that is NOT tainted → safe
            varTainted = false;
          } else if (
            getM &&
            !taintedMapKeysInner.has(`${getM[1]}[${getM[2]}]`)
          ) {
            // .get() with a non-tainted key → safe
            varTainted = false;
          }
        }
      }
    }
    // Fallback: forward taint propagation through intermediate variables.
    // The main loop above only checks direct param references in returnVar's
    // assignment RHS. This handles the OWASP "chain of propagators" pattern:
    //   a = param; sb = new StringBuilder(a); map.put("k", sb.toString());
    //   c = map.get("k"); d = c.substring(..); e = Base64(d); f = e.split(..);
    //   bar = thing.doSomething(f); return bar;
    if (!varTainted) {
      const innerTainted = new Set<string>([paramName]);
      const innerMapKeys = new Set<string>();
      for (let fi = 0; fi < liveLines.length; fi++) {
        const fl = liveLines[fi].text;
        // Check if any tainted var appears on this line (excluding LHS of assignment)
        let hasTaint = false;
        for (const tv of innerTainted) {
          if (
            identRegex(tv).test(fl) &&
            !fl.includes(tv + " =") &&
            !fl.startsWith(tv + " =")
          ) {
            hasTaint = true;
            break;
          }
        }
        // Also check if this line gets from a tainted map key (no direct tainted var needed)
        if (!hasTaint) {
          const getCheck = fl.match(
            /\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*"([^"]+)"\s*\)/,
          );
          if (getCheck && innerMapKeys.has(`${getCheck[1]}[${getCheck[2]}]`))
            hasTaint = true;
        }
        // Multiline: if assignment has empty/unclosed RHS, check continuation lines
        if (!hasTaint && (fl.endsWith("=") || hasUnclosedParen(fl))) {
          for (let k = fi + 1; k < liveLines.length && k <= fi + 8; k++) {
            for (const tv of innerTainted) {
              if (
                identRegex(tv).test(liveLines[k].text)
              ) {
                hasTaint = true;
                break;
              }
            }
            if (hasTaint) break;
            if (
              !hasUnclosedParen(liveLines[k].text) &&
              !liveLines[k].text.endsWith("=")
            )
              break;
          }
        }
        if (!hasTaint) {
          // Kill taint: if a tainted var is reassigned from a non-tainted source, remove it.
          for (const m of fl.matchAll(/([A-Za-z_$][\w$]*)\s*=(?!=)/g)) {
            if (
              innerTainted.has(m[1]) &&
              !/^(if|for|while|switch|return|catch|new)$/.test(m[1])
            ) {
              innerTainted.delete(m[1]);
            }
          }
          continue;
        }
        // Sanitizer gate: if this line applies a known sanitizer, taint is killed.
        if (sanitizers.some((s) => fl.includes(s))) continue;
        // Ternary with constant condition: if tainted var is only in the dead branch, skip.
        const rhsForTernary = fl.includes("=")
          ? fl
              .slice(fl.indexOf("=") + 1)
              .replace(/;\s*$/, "")
              .trim()
          : fl.replace(/;\s*$/, "").trim();
        const ternaryInner = splitTernary(rhsForTernary);
        if (ternaryInner) {
          const evalCondInner = evalConstCondition(
            ternaryInner.condition,
            bodyLines,
            liveLines[fi].idx,
          );
          if (evalCondInner !== null) {
            const deadBr = evalCondInner
              ? ternaryInner.falseBranch
              : ternaryInner.trueBranch;
            const liveBr = evalCondInner
              ? ternaryInner.trueBranch
              : ternaryInner.falseBranch;
            let inLive = false,
              inDead = false;
            for (const tv of innerTainted) {
              const re = identRegex(tv);
              if (re.test(liveBr)) inLive = true;
              if (re.test(deadBr)) inDead = true;
            }
            if (inDead && !inLive) continue;
          }
        }
        // Propagate to assigned variables on this line
        for (const m of fl.matchAll(/([A-Za-z_$][\w$]*)\s*=(?!=)/g)) {
          if (!/^(if|for|while|switch|return|catch|new)$/.test(m[1]))
            innerTainted.add(m[1]);
        }
        // StringBuilder: new StringBuilder(tainted) or sb.append(tainted)
        const sbM2 = fl.match(
          /\b([A-Za-z_$][\w$]*)\s*(?:=\s*new\s+StringBuilder\s*\(|\.\s*(?:append|replace|insert|delete)\s*\()/,
        );
        if (sbM2) innerTainted.add(sbM2[1]);
        // HashMap put → track tainted key
        const putM2 = fl.match(
          /\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\(\s*"([^"]+)"\s*,/,
        );
        if (putM2) innerMapKeys.add(`${putM2[1]}[${putM2[2]}]`);
        // HashMap get → propagate from tainted key
        const getM2 = fl.match(
          /([A-Za-z_$][\w$]*)\s*=\s*(?:\([^)]*\)\s*)?([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*"([^"]+)"\s*\)/,
        );
        if (getM2 && innerMapKeys.has(`${getM2[2]}[${getM2[3]}]`))
          innerTainted.add(getM2[1]);
      }
      if (innerTainted.has(returnVar)) varTainted = true;
    }
    if (!varTainted) {
      safe.add(methodName);
      ranges.push([bodyStart, bodyEnd]);
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  return { safeMethods: safe, safeRanges: ranges };
}

// ==================== DEAD-BRANCH TRACKING ====================

/**
 * Update the dead-branch state for multi-line if/else and switch constructs.
 * Called at the start of each line iteration BEFORE taint processing.
 *
 * Handles:
 *  - Multi-line `else` blocks following a provably-true if condition (else is dead).
 *  - Switch statements with a provably-constant target: non-matching cases are dead.
 */
function updateDeadBranch(
  state: DeadBranchState,
  trimmed: string,
  lines: string[],
  lineIdx: number,
): void {
  // ── Multi-line else tracking ──
  if (state.kind === "if-else") {
    if (state.braceDepth === -1) {
      // Waiting for the else block to start (if-body is live).
      if (trimmed.match(/^\}\s*else\s*\{/) || trimmed.startsWith("else")) {
        state.dead = true;
        state.braceDepth = trimmed.includes("{") ? 1 : 0;
      } else if (trimmed === "}" || trimmed === "};") {
        // if-block closed without else — cancel tracking.
        state.kind = "none";
        state.dead = false;
      }
      // Otherwise still in the live if-body — do nothing.
    } else {
      // Inside the dead else block — track braces until it closes.
      // If braceDepth === 0, this was a single-line else (e.g., `else bar = "safe";`).
      // The else line itself was already processed as dead; reset for subsequent lines.
      if (state.braceDepth === 0) {
        state.dead = false;
        state.kind = "none";
        return;
      }
      if (trimmed === "}" || trimmed === "};") {
        state.braceDepth--;
        if (state.braceDepth <= 0) {
          state.dead = false;
          state.kind = "none";
        }
      } else if (trimmed.includes("{")) {
        state.braceDepth++;
      }
    }
    return;
  }

  // ── Switch tracking ──
  if (state.kind === "switch") {
    if (trimmed === "}" || trimmed.startsWith("}")) {
      // End of switch block.
      state.dead = false;
      state.kind = "none";
      state.switchValue = null;
      state.caseLive = false;
      return;
    }
    const caseMatch = trimmed.match(/^case\s+(.+?)\s*:/);
    if (caseMatch) {
      const caseVal = resolveCaseValue(caseMatch[1].trim());
      const matches = caseVal !== null && caseVal === state.switchValue;
      if (matches) {
        state.caseLive = true;
        state.dead = false;
      } else if (!state.caseLive) {
        // Only mark dead if no prior case in this group matched.
        // (Consecutive labels like `case 'C': case 'D':` form a group;
        // if 'C' matched, 'D' must NOT override to dead.)
        state.dead = true;
      }
      return;
    }
    if (trimmed.startsWith("default")) {
      // default is live only if no specific case matched.
      state.dead = !state.caseLive;
      return;
    }
    if (trimmed.startsWith("break")) {
      // After break, the current case group ends. Reset for next group.
      state.caseLive = false;
      state.dead = true;
    }
    return;
  }

  // ── Detect new switch entry ──
  const switchMatch = trimmed.match(/^switch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/);
  if (switchMatch) {
    const val = resolveSwitchConstValue(lines, lineIdx, switchMatch[1]);
    if (val !== null) {
      state.kind = "switch";
      state.switchValue = val;
      state.caseLive = false;
      state.dead = true; // dead until a matching case is found
    }
    return;
  }

  // ── Detect multi-line if with constant condition followed by else block ──
  // Pattern: `if (condition) {` where condition is provably constant.
  const ifBlockMatch = trimmed.match(/^if\s*\((.+)\)\s*\{$/);
  if (ifBlockMatch) {
    const condEval = evalConstCondition(ifBlockMatch[1].trim(), lines, lineIdx);
    if (condEval === true) {
      // Condition always true → the else block (when we find it) is dead.
      // Look ahead for the matching `} else {`.
      let depth = 1;
      let foundElse = false;
      for (let k = lineIdx + 1; k < lines.length && k <= lineIdx + 30; k++) {
        const l = lines[k].trim();
        for (const ch of l) {
          if (ch === "{") depth++;
          else if (ch === "}") depth--;
        }
        if (depth === 0) {
          if (
            l.match(/^\}\s*else\s*\{/) ||
            (k + 1 < lines.length && lines[k + 1].trim().startsWith("else"))
          ) {
            foundElse = true;
          }
          break;
        }
      }
      if (foundElse) {
        state.kind = "if-else";
        state.dead = false; // if-body is live for now
        state.braceDepth = -1; // signal: waiting for else
      }
    } else if (condEval === false) {
      // Condition always false → the if-body is dead, else is live.
      state.kind = "if-else";
      state.dead = true;
      state.braceDepth = 1;
    }
    return;
  }

  // ── Detect standalone `else` line following a brace-less if with constant condition ──
  // Pattern: previous line `if (const_cond) stmt;` and this line `else stmt;`
  if (trimmed.startsWith("else") && !trimmed.startsWith("else if")) {
    for (let k = lineIdx - 1; k >= Math.max(0, lineIdx - 3); k--) {
      const prev = lines[k].trim();
      if (!prev || prev.startsWith("//") || prev === "}") continue;
      const ifMatch = prev.match(/^if\s*\((.+)\)/);
      if (ifMatch) {
        const condEval = evalConstCondition(ifMatch[1].trim(), lines, k);
        if (condEval === true) {
          // Condition always true → this else line is dead.
          state.dead = true;
          state.kind = "if-else";
          state.braceDepth = trimmed.includes("{") ? 1 : 0;
        }
      }
      break;
    }
  }
}

/**
 * Check if an assignment at `assignIdx` in `line` is in the dead else portion
 * of a SINGLE-LINE if/else with a provably-constant condition.
 *
 * Pattern: `if (const_cond) var = safe; else var = param;`
 * If the condition is always true, assignments after `else` are dead.
 * If the condition is always false, assignments before `else` are dead.
 */
function isInDeadSingleLineElse(
  line: string,
  assignIdx: number,
  lines: string[],
  lineIdx: number,
): boolean {
  const trimmed = line.trim();
  // Must look like a single-line if/else (both branches on one line).
  if (!trimmed.startsWith("if") && !trimmed.startsWith("if (")) return false;
  if (!trimmed.includes("else")) return false;

  // Extract condition between first `(` and its matching `)`.
  let depth = 0;
  let condStart = -1;
  let condEnd = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === "(" && condStart < 0) {
      condStart = i + 1;
      depth = 1;
    } else if (trimmed[i] === "(" && condStart >= 0) depth++;
    else if (trimmed[i] === ")" && condStart >= 0) {
      depth--;
      if (depth === 0) {
        condEnd = i;
        break;
      }
    }
  }
  if (condStart < 0 || condEnd < 0) return false;
  const condition = trimmed.slice(condStart, condEnd);
  const condEval = evalConstCondition(condition, lines, lineIdx);
  if (condEval === null) return false;

  // Find the `else` keyword position (after the condition's closing paren).
  const elseIdx = trimmed.indexOf("else", condEnd);
  if (elseIdx < 0) return false;

  // Determine if the assignment is in the dead portion.
  // assignIdx is relative to the ORIGINAL line (not trimmed). Adjust.
  const offset = line.length - line.trimStart().length;
  const assignInTrimmed = assignIdx - offset;

  if (condEval === true) {
    // Condition always true → else branch is dead.
    return assignInTrimmed > elseIdx;
  } else {
    // Condition always false → if-true branch is dead.
    return assignInTrimmed < elseIdx && assignInTrimmed > condEnd;
  }
}

/**
 * Resolve the constant value of a switch target variable by scanning backwards.
 * Handles patterns like:
 *   - `char switchTarget = guess.charAt(1);` with `String guess = "ABC";`
 *   - `int switchTarget = 2;`
 * Returns the resolved value as a string (e.g. "B" or "2"), or null.
 */
function resolveSwitchConstValue(
  lines: string[],
  lineIdx: number,
  varName: string,
): string | null {
  const re = new RegExp(
    `(?:^|[;{}\\s])(?:final\\s+|static\\s+)*(?:char|int|String|long|short|byte|Character|Integer)?\\s*${escapeRegex(varName)}\\s*=\\s*(.+?)\\s*;`,
  );
  for (let j = lineIdx - 1; j >= Math.max(0, lineIdx - 15); j--) {
    const m = re.exec(lines[j]);
    if (!m) continue;
    const rhs = m[1].trim();

    // charAt(N) on a string variable: `guess.charAt(1)`
    const charAtMatch = rhs.match(
      /([A-Za-z_$][\w$]*)\s*\.\s*charAt\s*\(\s*(\d+)\s*\)/,
    );
    if (charAtMatch) {
      const strVal = resolveLocalStringConst(lines, j, charAtMatch[1]);
      if (strVal !== null) {
        const idx = parseInt(charAtMatch[2], 10);
        if (idx < strVal.length) return strVal[idx];
      }
      return null;
    }

    // Character literal: 'B'
    const charLit = rhs.match(/^'([^']*)'$/);
    if (charLit) return charLit[1];

    // String literal: "B"
    const strLit = rhs.match(/^"([^"]*)"$/);
    if (strLit) return strLit[1];

    // Numeric literal
    if (/^-?\d+$/.test(rhs)) return rhs;

    return null;
  }
  return null;
}

/** Resolve a local String constant by scanning backwards (e.g. `String guess = "ABC";`). */
function resolveLocalStringConst(
  lines: string[],
  lineIdx: number,
  varName: string,
): string | null {
  const re = new RegExp(
    `(?:^|[;{}\\s])(?:final\\s+|static\\s+)*(?:String)?\\s*${escapeRegex(varName)}\\s*=\\s*"([^"]*)"\\s*;`,
  );
  for (let k = lineIdx - 1; k >= Math.max(0, lineIdx - 10); k--) {
    const m = lines[k].match(re);
    if (m) return m[1];
  }
  // Also check the same line (e.g. `String guess = "ABC"; char switchTarget = guess.charAt(1);`)
  const sameLine = lines[lineIdx].match(re);
  if (sameLine) return sameLine[1];
  return null;
}

/** Resolve a case label value to a comparable string. */
function resolveCaseValue(raw: string): string | null {
  // Character literal: 'B'
  const charLit = raw.match(/^'([^']*)'$/);
  if (charLit) return charLit[1];
  // Numeric literal
  if (/^-?\d+$/.test(raw)) return raw;
  // String literal: "B"
  const strLit = raw.match(/^"([^"]*)"$/);
  if (strLit) return strLit[1];
  return null;
}

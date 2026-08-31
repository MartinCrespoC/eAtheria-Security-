// Test the ternary evaluation for BenchmarkTest01440 pattern

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function splitTernary(expr: string): { condition: string; trueBranch: string; falseBranch: string } | null {
  let depth = 0;
  let qIdx = -1;
  let cIdx = -1;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "?" && depth === 0 && qIdx < 0) { qIdx = i; }
    else if (ch === ":" && depth === 0 && qIdx >= 0 && cIdx < 0) { cIdx = i; }
  }
  if (qIdx < 0 || cIdx < 0) return null;
  return {
    condition: expr.slice(0, qIdx).trim(),
    trueBranch: expr.slice(qIdx + 1, cIdx).trim(),
    falseBranch: expr.slice(cIdx + 1).trim(),
  };
}

function resolveLocalNumericConst(lines: string[], lineIdx: number, varName: string): number | null {
  const re = new RegExp(
    `(?:^|[;{}\\s])(?:final\\s+|static\\s+)*(?:int|long|short|byte|float|double|Integer|Long|Double|Float|Short|Byte)?\\s*${escapeRegex(varName)}\\s*=\\s*(-?[\\d.]+)\\s*[;]`
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

function evalConstCondition(cond: string, lines?: string[], lineIdx?: number): boolean | null {
  let expr = cond;
  const identifiers = expr.match(/[A-Za-z_$][\w$]*/g);
  if (identifiers && lines && lineIdx !== undefined) {
    for (const ident of identifiers) {
      if (/^(true|false|null|undefined|NaN|Infinity)$/.test(ident)) continue;
      const val = resolveLocalNumericConst(lines, lineIdx, ident);
      if (val !== null) {
        expr = expr.replace(new RegExp(`\\b${escapeRegex(ident)}\\b`, "g"), String(val));
      } else {
        return null;
      }
    }
  } else if (identifiers) {
    return null;
  }
  if (/[A-Za-z_$]/.test(expr)) return null;
  try {
    const result = eval(expr);
    if (typeof result === "boolean") return result;
    if (typeof result === "number") return result !== 0;
  } catch { /* not evaluable */ }
  return null;
}

// Test with BenchmarkTest01440 pattern
const bodyLines = [
  "String bar;",
  "// Simple ? condition that assigns constant to bar on true condition",
  "int num = 106;",
  'bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;',
  "return bar;",
];

const rhs = '(7 * 18) + num > 200 ? "This_should_always_happen" : param';
const ternary = splitTernary(rhs);
console.log("Ternary:", ternary);

if (ternary) {
  const lineIdx = 3; // index of the bar = ... line in bodyLines
  const evalCond = evalConstCondition(ternary.condition, bodyLines, lineIdx);
  console.log("Condition:", ternary.condition);
  console.log("Eval result:", evalCond);
  
  if (evalCond !== null) {
    const liveBranch = evalCond ? ternary.trueBranch : ternary.falseBranch;
    const deadBranch = evalCond ? ternary.falseBranch : ternary.trueBranch;
    console.log("Live branch:", liveBranch);
    console.log("Dead branch:", deadBranch);
    
    const paramRe = /\bparam\b/;
    console.log("Param in dead branch:", paramRe.test(deadBranch));
    console.log("Param in live branch:", paramRe.test(liveBranch));
  }
}

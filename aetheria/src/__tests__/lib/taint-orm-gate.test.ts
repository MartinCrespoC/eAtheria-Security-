import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/db", () => ({
  prisma: {
    falsePositivePattern: { findMany: vi.fn() },
  },
}));

import { prisma } from "@/lib/db";
import { runTaintAnalysis, type TaintRulesBundle } from "@/lib/analysis/engines/taint-engine";
import { FalsePositiveDetector } from "@/lib/analysis/false-positive-detector";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = prisma as any;

const SQLI_SINK = {
  language: "typescript",
  pattern: ".findOne(",
  cwe: "CWE-89",
  category: "SQL Injection",
  severity: "HIGH",
  owasp2021: "A03:2021",
};

const rules: TaintRulesBundle = {
  sources: [],
  sinks: [SQLI_SINK],
  sanitizers: [],
};

describe("taint engine — ORM parameterized repository gate (CWE-89)", () => {
  it("suppresses TypeORM findOne({ where: … }) with tainted scalar values", () => {
    const code = `
export class UsersService {
  async remove(tenantId: string, id: string) {
    const user = await this.users.findOne({ where: { id, tenantId } });
    if (!user) throw new NotFoundException();
    await this.users.remove(user);
  }
}`;
    const findings = runTaintAnalysis(code, "users.service.ts", "typescript", rules);
    expect(findings.filter((f) => f.cwe === "CWE-89")).toHaveLength(0);
  });

  it("suppresses multiline TypeORM findOne({\\n where: … })", () => {
    const code = `
export class AuthService {
  async registerAdmin(email: string) {
    const existing = await this.users.findOne({
      where: { email: email.toLowerCase() },
    });
    return existing;
  }
}`;
    const findings = runTaintAnalysis(code, "auth.service.ts", "typescript", rules);
    expect(findings.filter((f) => f.cwe === "CWE-89")).toHaveLength(0);
  });

  it("keeps Mongoose-style findOne({ email: tainted }) without where clause", () => {
    const code = `
export async function login(email: string) {
  const user = await User.findOne({ email });
  return user;
}`;
    const findings = runTaintAnalysis(code, "Auth.js", "typescript", rules);
    expect(findings.filter((f) => f.cwe === "CWE-89").length).toBeGreaterThan(0);
  });

  it("keeps findOne when a whole tainted object is spread into the query", () => {
    const code = `
export async function search(query: Record<string, unknown>) {
  return this.users.findOne({ where: { ...query } });
}`;
    const findings = runTaintAnalysis(code, "users.service.ts", "typescript", rules);
    expect(findings.filter((f) => f.cwe === "CWE-89").length).toBeGreaterThan(0);
  });

  it("keeps findOne with $-prefixed operator keys (NoSQL operator injection)", () => {
    const code = `
export async function adv(filter: string) {
  return this.users.findOne({ where: { $where: filter } });
}`;
    const findings = runTaintAnalysis(code, "users.service.ts", "typescript", rules);
    expect(findings.filter((f) => f.cwe === "CWE-89").length).toBeGreaterThan(0);
  });
});

describe("FP detector — CWE-347 pinned JWT algorithms", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.falsePositivePattern.findMany.mockResolvedValue([]);
  });

  it("marks pinned algorithms: ['HS256'] as false positive (mitigation present)", async () => {
    const detector = new FalsePositiveDetector();
    await detector.initialize();
    const snippet = `      algorithms: ['HS256'],`;
    const result = await detector.checkVulnerability({
      cweId: "CWE-347",
      code: snippet,
      language: "typescript",
      line: 15,
      file: "jwt.strategy.ts",
      severity: "CRITICAL",
      codeSnippet: snippet,
    });
    expect(result.isFalsePositive).toBe(true);
    expect(result.matchedPattern?.id).toBe("builtin-jwt-algorithms-pinned");
  });

  it("does NOT suppress when no algorithm allowlist is pinned", async () => {
    const detector = new FalsePositiveDetector();
    await detector.initialize();
    const snippet = `      secretOrKey: requireEnv('JWT_SECRET_KEY'),`;
    const result = await detector.checkVulnerability({
      cweId: "CWE-347",
      code: snippet,
      language: "typescript",
      line: 12,
      file: "jwt.strategy.ts",
      severity: "CRITICAL",
      codeSnippet: snippet,
    });
    expect(result.isFalsePositive).toBe(false);
  });
});

import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey, hasScope } from "@/lib/api-auth";
import { rateLimit, getClientIp } from "@/lib/rate-limit";
import { generateWithGemini } from "@/lib/ai";

/**
 * POST /api/v1/fix-pr
 * Generate fix patches for vulnerabilities. Returns unified diff patches
 * that can be applied to create a PR.
 *
 * Headers:
 *   Authorization: Bearer aeth_xxxxx
 *
 * Body:
 *   {
 *     "files": [
 *       {
 *         "path": "src/auth/login.ts",
 *         "code": "... source code ...",
 *         "vulnerabilities": [
 *           { "title": "SQL Injection", "lineStart": 42, "description": "...", "fix": "..." }
 *         ]
 *       }
 *     ],
 *     "branchName": "aetheria/security-fixes",   // optional
 *     "commitMessage": "fix: security issues"     // optional
 *   }
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);
  const rl = rateLimit(`api:fixpr:${ip}`, { maxRequests: 10, windowMs: 60_000 });
  if (!rl.success) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Max 10 fix-pr requests/minute." },
      { status: 429 }
    );
  }

  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json(
      { error: "Invalid or expired API key." },
      { status: 401 }
    );
  }

  if (!hasScope(ctx, "analysis:create")) {
    return NextResponse.json(
      { error: "API key does not have 'analysis:create' scope." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const { files, branchName, commitMessage } = body;

    if (!Array.isArray(files) || files.length === 0) {
      return NextResponse.json(
        { error: "Field 'files' is required and must be a non-empty array." },
        { status: 400 }
      );
    }

    const patches: { path: string; originalCode: string; fixedCode: string; diff: string; changes: string[] }[] = [];

    for (const file of files) {
      if (!file.path || !file.code) continue;

      const vulnDescriptions = (file.vulnerabilities || [])
        .map((v: { title: string; lineStart?: number; description?: string; fix?: string }, i: number) =>
          `${i + 1}. [Line ${v.lineStart || "?"}] ${v.title}: ${v.description || ""}${v.fix ? `\n   Suggested fix: ${v.fix}` : ""}`
        )
        .join("\n");

      const prompt = `You are EATHERIA Security Fix Generator. Apply ALL the security fixes to the following code.

File: ${file.path}

VULNERABILITIES TO FIX:
${vulnDescriptions}

ORIGINAL CODE:
\`\`\`
${file.code}
\`\`\`

Return ONLY valid JSON with this structure:
{
  "fixedCode": "the complete fixed source code with all vulnerabilities resolved",
  "changes": [
    "Brief description of each change made"
  ]
}

Rules:
- Fix ALL listed vulnerabilities
- Preserve the original code style, comments, and formatting
- Only change what is necessary to fix the vulnerabilities
- Do not add unnecessary imports or refactoring
- The fixedCode must be the COMPLETE file, not just snippets`;

      const result = await generateWithGemini(prompt, {
        temperature: 0.1,
        maxOutputTokens: 16384,
        companyId: ctx.companyId,
      });

      const jsonMatch = result.text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        const fixedCode = parsed.fixedCode || file.code;
        const changes = parsed.changes || [];

        // Generate a simple unified diff
        const diff = generateUnifiedDiff(file.path, file.code, fixedCode);

        patches.push({
          path: file.path,
          originalCode: file.code,
          fixedCode,
          diff,
          changes,
        });
      }
    }

    return NextResponse.json({
      patches,
      branchName: branchName || "aetheria/security-fixes",
      commitMessage: commitMessage || `fix(security): resolve ${patches.reduce((sum, p) => sum + p.changes.length, 0)} vulnerabilities\n\nFixed by EATHERIA Security MCP`,
      totalFiles: patches.length,
      totalChanges: patches.reduce((sum, p) => sum + p.changes.length, 0),
    });
  } catch (error) {
    console.error("Fix PR error:", error);
    return NextResponse.json(
      { error: "Internal server error during fix generation." },
      { status: 500 }
    );
  }
}

function generateUnifiedDiff(filePath: string, original: string, fixed: string): string {
  const origLines = original.split("\n");
  const fixedLines = fixed.split("\n");

  let diff = `--- a/${filePath}\n+++ b/${filePath}\n`;

  // Simple line-by-line diff (not a full Myers algorithm, but useful for display)
  const maxLines = Math.max(origLines.length, fixedLines.length);
  let hunkStart = -1;
  let hunkLines: string[] = [];
  const context = 3;

  for (let i = 0; i < maxLines; i++) {
    const origLine = i < origLines.length ? origLines[i] : undefined;
    const fixedLine = i < fixedLines.length ? fixedLines[i] : undefined;

    if (origLine !== fixedLine) {
      if (hunkStart === -1) {
        hunkStart = Math.max(0, i - context);
        // Add leading context
        for (let j = hunkStart; j < i; j++) {
          if (j < origLines.length) hunkLines.push(` ${origLines[j]}`);
        }
      }
      if (origLine !== undefined) hunkLines.push(`-${origLine}`);
      if (fixedLine !== undefined) hunkLines.push(`+${fixedLine}`);
    } else if (hunkStart !== -1) {
      hunkLines.push(` ${origLine}`);
      // Check if we're past the context window
      const lastChange = hunkLines.findLastIndex((l) => l.startsWith("+") || l.startsWith("-"));
      if (hunkLines.length - lastChange > context) {
        diff += `@@ -${hunkStart + 1} +${hunkStart + 1} @@\n`;
        diff += hunkLines.join("\n") + "\n";
        hunkStart = -1;
        hunkLines = [];
      }
    }
  }

  // Flush remaining hunk
  if (hunkStart !== -1) {
    diff += `@@ -${hunkStart + 1} +${hunkStart + 1} @@\n`;
    diff += hunkLines.join("\n") + "\n";
  }

  return diff;
}

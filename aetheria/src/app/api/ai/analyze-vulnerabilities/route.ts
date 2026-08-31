/**
 * AI-Powered Vulnerability Analysis API
 * POST /api/ai/analyze-vulnerabilities
 */

import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth";
import { analyzeVulnerabilities, generateSecurityFixes } from "@/lib/ai/pentesting/vulnerability-analyzer";
import { validateInput, analysisSchema } from "@/lib/validation/schemas";

export async function POST(req: NextRequest) {
  try {
    const session = await requireAuth();
    const body = await req.json();

    // Validate input
    const validation = validateInput(analysisSchema, body);

    const { code, language, filePath, context, analysisDepth, generateFixes } = validation;

    // Analyze vulnerabilities
    const result = await analyzeVulnerabilities({
      code,
      language,
      filePath,
      context,
      analysisDepth: analysisDepth || "standard",
      userId: session.user.id,
      companyId: session.user.companyId || "",
    });

    // Optionally generate fixes
    let fixes;
    if (generateFixes && result.vulnerabilities.length > 0) {
      fixes = await generateSecurityFixes(
        result.vulnerabilities,
        code,
        session.user.id,
        session.user.companyId || ""
      );
    }

    return NextResponse.json({
      success: true,
      analysis: result,
      fixes,
    });
  } catch (error) {
    console.error("Vulnerability analysis error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Analysis failed",
      },
      { status: 500 }
    );
  }
}

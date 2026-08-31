/**
 * @deprecated Use `@/lib/ai` instead. This file is kept for backward compatibility.
 * All new code should import from `@/lib/ai`.
 */
import { generateWithGemini, type GenerateOptions, type AIResponse } from "./index";

export { generateWithGemini };
export type GeminiGenerateOptions = GenerateOptions;
export type GeminiResponse = AIResponse;

import { prisma } from "../db";

export async function getDefaultModel(): Promise<{
  modelId: string;
  name: string;
  inputCost: number;
  outputCost: number;
}> {
  const model = await prisma.aIModel.findFirst({
    where: { isDefault: true, isActive: true },
  });

  if (model) {
    return {
      modelId: model.modelId,
      name: model.name,
      inputCost: Number(model.inputTokenCost),
      outputCost: Number(model.outputTokenCost),
    };
  }

  return {
    modelId: "gemini-2.5-flash-lite",
    name: "Gemini 2.5 Flash-Lite",
    inputCost: 0.075,
    outputCost: 0.3,
  };
}

export async function validateVulnerabilityWithAI(
  vulnerability: {
    title: string;
    description: string;
    codeSnippet?: string;
    filePath?: string;
    cweId?: string;
  },
  companyId?: string
): Promise<{
  isFalsePositive: boolean;
  confidence: number;
  reason: string;
  smartFix?: string;
}> {
  const prompt = `You are a senior application security expert. Analyze this vulnerability and determine if it's a real issue or a false positive.

Vulnerability:
- Title: ${vulnerability.title}
- Description: ${vulnerability.description}
- CWE: ${vulnerability.cweId || "N/A"}
- File: ${vulnerability.filePath || "N/A"}
- Code:
\`\`\`
${vulnerability.codeSnippet || "No code snippet available"}
\`\`\`

Respond ONLY with a valid JSON object with this structure:
{
  "isFalsePositive": boolean,
  "confidence": number (0-1),
  "reason": "explanation",
  "smartFix": "fixed code example"
}`;

  try {
    const response = await generateWithGemini(prompt, {
      temperature: 0.2,
      maxOutputTokens: 2048,
      companyId,
    });

    const jsonMatch = response.text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        isFalsePositive: false,
        confidence: 0.5,
        reason: "Unable to parse AI response",
      };
    }

    const parsed = JSON.parse(jsonMatch[0]);
    return {
      isFalsePositive: parsed.isFalsePositive || false,
      confidence: parsed.confidence || 0.5,
      reason: parsed.reason || "No reason provided",
      smartFix: parsed.smartFix,
    };
  } catch (error) {
    console.error("Error validating with AI:", error);
    return {
      isFalsePositive: false,
      confidence: 0,
      reason: "AI validation failed",
    };
  }
}

export async function analyzeCodeWithAI(
  code: string,
  language: string,
  filePath: string,
  companyId?: string
): Promise<{
  vulnerabilities: Array<{
    title: string;
    description: string;
    severity: string;
    cweId?: string;
    lineStart?: number;
    lineEnd?: number;
    smartFix?: string;
  }>;
}> {
  const prompt = `You are a security scanner analyzing code for vulnerabilities. Analyze this ${language} code and identify security issues.

File: ${filePath}
Code:
\`\`\`${language}
${code}
\`\`\`

Return ONLY valid JSON with this structure:
{
  "vulnerabilities": [
    {
      "title": "vulnerability name",
      "description": "detailed description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cweId": "CWE-XX",
      "lineStart": number,
      "lineEnd": number,
      "smartFix": "fixed code"
    }
  ]
}`;

  try {
    const response = await generateWithGemini(prompt, {
      temperature: 0.2,
      maxOutputTokens: 8192,
      companyId,
    });

    const jsonMatch = response.text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return { vulnerabilities: [] };

    return JSON.parse(jsonMatch[0]);
  } catch (error) {
    console.error("Error analyzing code with AI:", error);
    return { vulnerabilities: [] };
  }
}

export async function generateMarketingContentWithAI(
  topic: string,
  type: "email" | "social" | "blog" | "ad",
  companyId?: string
): Promise<string> {
  const prompt = `Generate compelling marketing content for EATHERIA Security Platform (an enterprise SAST/DAST/SCA platform with AI).

Topic: ${topic}
Type: ${type}

Keep it professional, tech-focused, and emphasize: AI-powered analysis, multi-standard compliance, enterprise security, cost-effectiveness vs Fortify.`;

  const response = await generateWithGemini(prompt, {
    temperature: 0.8,
    maxOutputTokens: 2048,
    companyId,
  });

  return response.text;
}

/**
 * Input Validation Schemas using Zod
 * Prevents injection attacks, validates data types, and enforces business rules
 */

import { z } from "zod";

// ==================== AUTH SCHEMAS ====================

export const loginSchema = z.object({
  email: z.string().email("Invalid email format").toLowerCase(),
  password: z.string().min(1, "Password required"),
  totpCode: z.string().optional(),
  srpProof: z.string().optional(),
});

export const registerSchema = z.object({
  email: z.string().email("Invalid email format").toLowerCase(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  firstName: z.string().min(1, "First name required").max(100),
  lastName: z.string().min(1, "Last name required").max(100),
  companyName: z.string().min(1, "Company name required").max(200),
});

export const passwordResetSchema = z.object({
  currentPassword: z.string().min(1, "Current password required"),
  newPassword: z.string().min(8, "Password must be at least 8 characters"),
});

// ==================== API KEY SCHEMAS ====================

export const apiKeySchema = z.object({
  name: z.string().min(1, "Name required").max(100),
  expiresAt: z.string().datetime().optional(),
});

// ==================== ANALYSIS SCHEMAS ====================

export const scanSchema = z.object({
  code: z.string().min(1, "Code required").max(1_000_000, "Code too large"),
  language: z.enum(["javascript", "typescript", "python", "java", "go", "rust", "php", "ruby"]),
  filename: z.string().optional(),
});

export const applicationSchema = z.object({
  name: z.string().min(1, "Name required").max(200),
  description: z.string().max(1000).optional(),
  repositoryUrl: z.string().url("Invalid URL").optional(),
});

// ==================== ADMIN SCHEMAS ====================

export const aiModelSchema = z.object({
  name: z.string().min(1, "Name required").max(100),
  provider: z.string().min(1, "Provider required"),
  modelId: z.string().min(1, "Model ID required"),
  inputTokenCost: z.number().min(0),
  outputTokenCost: z.number().min(0),
  maxInputTokens: z.number().int().min(1),
  maxOutputTokens: z.number().int().min(1),
  isActive: z.boolean().default(true),
  isDefault: z.boolean().default(false),
  providerId: z.string().optional(),
});

export const aiProviderSchema = z.object({
  slug: z.string().min(1, "Slug required").max(50).regex(/^[a-z0-9-]+$/, "Invalid slug format"),
  name: z.string().min(1, "Name required").max(100),
  type: z.enum([
    "openai-compatible",
    "anthropic",
    "google-gemini",
    "google-gemini-oauth",
    "azure-openai",
    "aws-bedrock",
    "copilot",
  ]),
  baseUrl: z.string().url("Invalid URL").optional(),
  apiKey: z.string().optional(),
  authType: z.enum(["api_key", "oauth", "aws_credentials"]).default("api_key"),
  isActive: z.boolean().default(false),
  config: z.record(z.string(), z.unknown()).optional(),
});

export const systemConfigSchema = z.object({
  key: z.string().min(1, "Key required").max(100),
  value: z.unknown(),
});

// ==================== USER SCHEMAS ====================

export const userProfileSchema = z.object({
  firstName: z.string().min(1, "First name required").max(100),
  lastName: z.string().min(1, "Last name required").max(100),
  phone: z.string().max(20).optional(),
  avatarUrl: z.string().url("Invalid URL").optional(),
  preferredLanguage: z.enum(["es", "en"]).default("es"),
  timezone: z.string().max(50).default("America/Mexico_City"),
});

export const userInviteSchema = z.object({
  email: z.string().email("Invalid email format").toLowerCase(),
  roleId: z.string().cuid("Invalid role ID"),
});

// ==================== COMPANY SCHEMAS ====================

export const companySchema = z.object({
  name: z.string().min(1, "Name required").max(200),
  email: z.string().email("Invalid email format"),
  phone: z.string().max(20).optional(),
  address: z.string().max(500).optional(),
  logoUrl: z.string().url("Invalid URL").optional(),
  primaryColor: z.string().regex(/^#[0-9A-Fa-f]{6}$/, "Invalid color format").optional(),
});

// ==================== GITHUB SCHEMAS ====================

export const githubConnectionSchema = z.object({
  repositoryUrl: z.string().url("Invalid URL"),
  branch: z.string().min(1, "Branch required").max(100).default("main"),
  accessToken: z.string().min(1, "Access token required"),
});

// ==================== ID VALIDATION ====================

export const idSchema = z.string().cuid("Invalid ID format");

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ==================== HELPER FUNCTIONS ====================

export function validateInput<T>(schema: z.ZodSchema<T>, data: unknown): T {
  return schema.parse(data);
}

export function validateInputSafe<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: result.error.issues.map((e: z.ZodIssue) => `${e.path.join(".")}: ${e.message}`).join(", "),
  };
}

// ─── AI Pentesting Schemas ────────────────────────────────────

export const analysisSchema = z.object({
  code: z.string().min(1, "Code is required"),
  language: z.string().optional(),
  filePath: z.string().optional(),
  context: z.object({
    framework: z.string().optional(),
    dependencies: z.array(z.string()).optional(),
    environment: z.string().optional(),
  }).optional(),
  analysisDepth: z.enum(["quick", "standard", "deep", "exhaustive"]).optional(),
  generateFixes: z.boolean().optional(),
});

export const exploitSchema = z.object({
  vulnerability: z.object({
    title: z.string().min(1),
    description: z.string().min(1),
    cweId: z.string().optional(),
    targetCode: z.string().optional(),
    targetUrl: z.string().url().optional(),
  }),
  targetEnvironment: z.object({
    os: z.string().optional(),
    language: z.string().optional(),
    framework: z.string().optional(),
    version: z.string().optional(),
  }).optional(),
  exploitType: z.enum(["poc", "full", "defensive"]).optional(),
});

export const networkAnalysisSchema = z.object({
  packets: z.array(z.object({
    timestamp: z.string(),
    sourceIP: z.string(),
    destIP: z.string(),
    sourcePort: z.number().int().min(0).max(65535),
    destPort: z.number().int().min(0).max(65535),
    protocol: z.string(),
    payloadSize: z.number().int().min(0),
    flags: z.string().optional(),
    payload: z.string().optional(),
  })),
  timeRange: z.object({
    start: z.string(),
    end: z.string(),
  }),
  metadata: z.object({
    networkSegment: z.string().optional(),
    captureInterface: z.string().optional(),
  }).optional(),
});

export const threatIntelSchema = z.object({
  iocs: z.array(z.object({
    type: z.enum(["ip", "domain", "url", "hash", "email", "cve"]),
    value: z.string().min(1),
    context: z.string().optional(),
    firstSeen: z.string().optional(),
    lastSeen: z.string().optional(),
  })),
});

/**
 * Threat Model Generation
 * Replicates codex-security threat-model skill + threat-model-guidance.md
 * Generates structured per-scan threat models using AI
 */

import { ANALYSIS_VOICE, JSON_OUTPUT_CONTRACT, truncateForPrompt } from "./prompts";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ThreatModelActor {
  name: string;
  description: string;
  capabilities: string[];
}

export interface ThreatModelBoundary {
  name: string;
  description: string;
  trustLevel: "high" | "medium" | "low";
}

export interface ThreatModelAsset {
  name: string;
  sensitivity: "critical" | "high" | "medium" | "low";
  location: string;
}

export interface ThreatModelThreat {
  id: string;
  description: string;
  actor: string;
  asset: string;
  likelihood: "high" | "medium" | "low";
  impact: "high" | "medium" | "low";
}

export interface ThreatModelData {
  content: string; // Full markdown
  actors: ThreatModelActor[];
  boundaries: ThreatModelBoundary[];
  assets: ThreatModelAsset[];
  threats: ThreatModelThreat[];
}

export interface RepoInfo {
  name?: string;
  languages: string[];
  frameworks?: string[];
  fileStructure?: string;
  dependencies?: string[];
  hasAuth?: boolean;
  hasApi?: boolean;
  hasDatabase?: boolean;
  hasFileUpload?: boolean;
  hasExternalServices?: boolean;
}

// ─── Prompt Builder ──────────────────────────────────────────────────────────

/**
 * Build prompt for AI threat model generation
 * Based on codex-security threat-model-guidance.md
 */
export function buildThreatModelPrompt(repoInfo: RepoInfo): string {
  const depsList = repoInfo.dependencies?.length
    ? repoInfo.dependencies.slice(0, 30).join(", ")
    : "Unknown";

  return `${ANALYSIS_VOICE}

## Task
Generate a comprehensive threat model for this software project. The threat model will guide all subsequent security analysis phases.

## Project Information
- Name: ${repoInfo.name || "Unknown"}
- Languages: ${repoInfo.languages.join(", ") || "Unknown"}
- Frameworks: ${repoInfo.frameworks?.join(", ") || "Not detected"}
- Dependencies: ${truncateForPrompt(depsList, 1000)}
${repoInfo.fileStructure ? `- File Structure:\n${truncateForPrompt(repoInfo.fileStructure, 2000)}` : ""}

## Detected Capabilities
- Authentication system: ${repoInfo.hasAuth ? "Yes" : "Not detected"}
- API endpoints: ${repoInfo.hasApi ? "Yes" : "Not detected"}
- Database access: ${repoInfo.hasDatabase ? "Yes" : "Not detected"}
- File upload handling: ${repoInfo.hasFileUpload ? "Yes" : "Not detected"}
- External service integration: ${repoInfo.hasExternalServices ? "Yes" : "Not detected"}

## Threat Model Guidance
Generate a repository-level threat model that would apply to ANY change in this repository.
Do not bias toward any specific vulnerability or recent change.

Include:
1. **Actors**: Who might attack this system? (external attacker, authenticated user, malicious insider, compromised dependency)
2. **Trust Boundaries**: Where do trust transitions occur? (internet→app, user→admin, app→database, app→external)
3. **Assets**: What is worth protecting? (user data, credentials, sessions, infrastructure, secrets)
4. **Threat Scenarios**: Concrete attack scenarios per STRIDE category:
   - Spoofing: Identity forgery, session hijacking
   - Tampering: Data modification, injection
   - Repudiation: Audit log bypass
   - Information Disclosure: Data leaks, side channels
   - Denial of Service: Resource exhaustion, crashes
   - Elevation of Privilege: AuthZ bypass, IDOR

${JSON_OUTPUT_CONTRACT}

## Response Format
{
  "content": "Full threat model as markdown text (include all sections below)",
  "actors": [{"name": "...", "description": "...", "capabilities": ["..."]}],
  "boundaries": [{"name": "...", "description": "...", "trustLevel": "high|medium|low"}],
  "assets": [{"name": "...", "sensitivity": "critical|high|medium|low", "location": "..."}],
  "threats": [{"id": "T1", "description": "...", "actor": "...", "asset": "...", "likelihood": "high|medium|low", "impact": "high|medium|low"}]
}`;
}

// ─── Response Parser ─────────────────────────────────────────────────────────

/**
 * Parse AI threat model response
 */
export function parseThreatModel(text: string): ThreatModelData | null {
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as Partial<ThreatModelData>;

    // Validate minimum required fields
    if (!parsed.actors && !parsed.threats) return null;

    return {
      content: parsed.content || buildMarkdownFromStructured(parsed),
      actors: Array.isArray(parsed.actors) ? parsed.actors : [],
      boundaries: Array.isArray(parsed.boundaries) ? parsed.boundaries : [],
      assets: Array.isArray(parsed.assets) ? parsed.assets : [],
      threats: Array.isArray(parsed.threats) ? parsed.threats : [],
    };
  } catch {
    // Fallback: use raw text as content
    if (text.length > 100) {
      return {
        content: text,
        actors: [],
        boundaries: [],
        assets: [],
        threats: [],
      };
    }
    return null;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildMarkdownFromStructured(data: Partial<ThreatModelData>): string {
  const sections: string[] = ["# Threat Model\n"];

  if (data.actors?.length) {
    sections.push("## Actors\n");
    for (const actor of data.actors) {
      sections.push(`### ${actor.name}\n${actor.description}\nCapabilities: ${actor.capabilities?.join(", ") || "N/A"}\n`);
    }
  }

  if (data.boundaries?.length) {
    sections.push("## Trust Boundaries\n");
    for (const b of data.boundaries) {
      sections.push(`- **${b.name}** (trust: ${b.trustLevel}): ${b.description}`);
    }
    sections.push("");
  }

  if (data.assets?.length) {
    sections.push("## Assets\n");
    for (const a of data.assets) {
      sections.push(`- **${a.name}** (sensitivity: ${a.sensitivity}): ${a.location}`);
    }
    sections.push("");
  }

  if (data.threats?.length) {
    sections.push("## Threat Scenarios\n");
    for (const t of data.threats) {
      sections.push(`### ${t.id}: ${t.description}\n- Actor: ${t.actor}\n- Target: ${t.asset}\n- Likelihood: ${t.likelihood}\n- Impact: ${t.impact}\n`);
    }
  }

  return sections.join("\n");
}

/**
 * Build a compact threat model context string for injection into other prompts
 * Token-optimized summary for use in attack-path and validation phases
 */
export function buildThreatModelContext(data: ThreatModelData, maxChars = 2000): string {
  const parts: string[] = [];

  if (data.actors.length > 0) {
    parts.push(`Actors: ${data.actors.map((a) => a.name).join(", ")}`);
  }

  if (data.boundaries.length > 0) {
    parts.push(`Trust boundaries: ${data.boundaries.map((b) => `${b.name}(${b.trustLevel})`).join(", ")}`);
  }

  if (data.assets.length > 0) {
    parts.push(`Protected assets: ${data.assets.map((a) => `${a.name}(${a.sensitivity})`).join(", ")}`);
  }

  if (data.threats.length > 0) {
    const topThreats = data.threats
      .filter((t) => t.likelihood === "high" || t.impact === "high")
      .slice(0, 5);
    if (topThreats.length > 0) {
      parts.push(`Key threats: ${topThreats.map((t) => t.description.slice(0, 80)).join("; ")}`);
    }
  }

  const result = `## Threat Model Context\n${parts.join("\n")}`;
  return truncateForPrompt(result, maxChars);
}

/**
 * Infer repo capabilities from file list for threat model generation
 */
export function inferRepoCapabilities(files: string[]): Partial<RepoInfo> {
  const lowerFiles = files.map((f) => f.toLowerCase());

  return {
    hasAuth: lowerFiles.some((f) =>
      f.includes("auth") || f.includes("login") || f.includes("session") || f.includes("jwt")
    ),
    hasApi: lowerFiles.some((f) =>
      f.includes("route") || f.includes("controller") || f.includes("handler") || f.includes("api")
    ),
    hasDatabase: lowerFiles.some((f) =>
      f.includes("model") || f.includes("schema") || f.includes("migration") || f.includes("prisma") || f.includes("query")
    ),
    hasFileUpload: lowerFiles.some((f) =>
      f.includes("upload") || f.includes("file") || f.includes("storage") || f.includes("multer")
    ),
    hasExternalServices: lowerFiles.some((f) =>
      f.includes("client") || f.includes("webhook") || f.includes("integration") || f.includes("sdk")
    ),
  };
}

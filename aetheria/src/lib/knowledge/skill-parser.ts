/**
 * BugHunter Skill Markdown Parser
 * Parses SKILL.md files from the Claude-BugHunter repository into structured data
 * for storage in the HuntSkill DB model.
 *
 * Skill structure (from 82 skills across 24 vuln classes):
 * - YAML frontmatter: name, description, sources, report_count
 * - ## Sections: Crown Jewel Targets, Attack Surface Signals, Methodology,
 *   Payload & Detection Patterns, Common Root Causes, Bypass Techniques,
 *   Gate 0 Validation, Real Impact Examples, Related Skills & Chains
 */

export interface ParsedSkill {
  slug: string;
  name: string;
  category: string;
  description: string;
  reportCount: number;
  sources: string[];
  rootCauses: { title: string; detail: string }[];
  attackSignals: { type: string; pattern: string; note: string }[];
  detectionPatterns: { name: string; pattern: string; language: string }[];
  bypassTechniques: string[];
  validationGate: { question: string; criteria: string }[];
  impactExamples: { scenario: string; description: string; cveIds: string[] }[];
  chains: { targetSkill: string; primitive: string }[];
  methodology: string;
  frameworks: string[];
  languages: string[];
}

interface Frontmatter {
  name: string;
  description: string;
  sources: string[];
  reportCount: number;
}

/** Extract YAML frontmatter from raw markdown */
function parseFrontmatter(raw: string): { frontmatter: Frontmatter; body: string } {
  const match = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) {
    return {
      frontmatter: { name: "", description: "", sources: [], reportCount: 0 },
      body: raw,
    };
  }

  const yamlBlock = match[1];
  const body = match[2];

  const name = yamlBlock.match(/^name:\s*(.+)$/m)?.[1]?.trim() || "";
  const description = yamlBlock.match(/^description:\s*(.+)$/m)?.[1]?.trim() || "";
  const sourcesRaw = yamlBlock.match(/^sources:\s*(.+)$/m)?.[1]?.trim() || "";
  const reportCountRaw = yamlBlock.match(/^report_count:\s*(\d+)/m)?.[1];

  const sources = sourcesRaw
    ? sourcesRaw.split(",").map((s) => s.trim()).filter(Boolean)
    : [];

  return {
    frontmatter: {
      name,
      description,
      sources,
      reportCount: reportCountRaw ? parseInt(reportCountRaw, 10) : 0,
    },
    body,
  };
}

/** Split body into sections by ## headings */
function splitSections(body: string): Map<string, string> {
  const sections = new Map<string, string>();
  const lines = body.split("\n");
  let currentHeading = "_intro";
  let currentContent: string[] = [];

  for (const line of lines) {
    const headingMatch = line.match(/^##\s+(.+)$/);
    if (headingMatch) {
      sections.set(currentHeading, currentContent.join("\n").trim());
      currentHeading = headingMatch[1].trim();
      currentContent = [];
    } else {
      currentContent.push(line);
    }
  }
  sections.set(currentHeading, currentContent.join("\n").trim());
  return sections;
}

/** Parse "Common Root Causes" section → numbered list items */
function parseRootCauses(content: string): { title: string; detail: string }[] {
  if (!content) return [];
  const causes: { title: string; detail: string }[] = [];
  // Match numbered items: "1. **Title** — detail" or "1. **Title** - detail"
  const items = content.split(/\n\d+\.\s+/).filter(Boolean);
  for (const item of items) {
    const boldMatch = item.match(/^\*\*(.+?)\*\*\s*[—–-]\s*([\s\S]*)/);
    if (boldMatch) {
      causes.push({ title: boldMatch[1].trim(), detail: boldMatch[2].trim().slice(0, 500) });
    } else {
      const plain = item.trim().slice(0, 500);
      if (plain.length > 10) {
        causes.push({ title: plain.slice(0, 80), detail: plain });
      }
    }
  }
  return causes.slice(0, 15);
}

/** Parse "Attack Surface Signals" section */
function parseAttackSignals(content: string): { type: string; pattern: string; note: string }[] {
  if (!content) return [];
  const signals: { type: string; pattern: string; note: string }[] = [];

  // Extract code blocks as URL/pattern signals
  const codeBlocks = content.match(/```[\w]*\n([\s\S]*?)```/g) || [];
  for (const block of codeBlocks) {
    const inner = block.replace(/```[\w]*\n?/g, "").replace(/```/g, "").trim();
    const lines = inner.split("\n").filter((l) => l.trim() && !l.startsWith("//") && !l.startsWith("#"));
    for (const line of lines.slice(0, 10)) {
      const type = line.includes("?") || line.includes("/") ? "url" : "pattern";
      signals.push({ type, pattern: line.trim().slice(0, 200), note: "" });
    }
  }

  // Extract bullet points as header/tech signals
  const bullets = content.match(/^[-*]\s+(.+)$/gm) || [];
  for (const bullet of bullets.slice(0, 15)) {
    const text = bullet.replace(/^[-*]\s+/, "").trim();
    const type = text.includes("header") || text.includes("X-") || text.includes("Server:")
      ? "header"
      : text.includes("JavaScript") || text.includes("JS") || text.includes("fetch(")
        ? "js"
        : "tech";
    signals.push({ type, pattern: text.slice(0, 200), note: "" });
  }

  return signals.slice(0, 30);
}

/** Parse "Payload & Detection Patterns" section */
function parseDetectionPatterns(content: string): { name: string; pattern: string; language: string }[] {
  if (!content) return [];
  const patterns: { name: string; pattern: string; language: string }[] = [];

  // Split by bold sub-headings within the section
  const subSections = content.split(/\*\*(.+?):?\*\*/).filter(Boolean);
  for (let i = 0; i < subSections.length - 1; i += 2) {
    const name = subSections[i]?.trim() || `Pattern ${patterns.length + 1}`;
    const block = subSections[i + 1] || "";

    // Extract code blocks
    const codeBlocks = block.match(/```(\w*)\n([\s\S]*?)```/g) || [];
    for (const cb of codeBlocks) {
      const langMatch = cb.match(/```(\w*)\n/);
      const lang = langMatch?.[1] || "text";
      const code = cb.replace(/```\w*\n?/g, "").replace(/```/g, "").trim();
      if (code.length > 5) {
        patterns.push({ name: name.slice(0, 100), pattern: code.slice(0, 1000), language: lang });
      }
    }
  }

  // If no sub-sections found, extract all code blocks directly
  if (patterns.length === 0) {
    const codeBlocks = content.match(/```(\w*)\n([\s\S]*?)```/g) || [];
    for (const cb of codeBlocks.slice(0, 8)) {
      const langMatch = cb.match(/```(\w*)\n/);
      const lang = langMatch?.[1] || "text";
      const code = cb.replace(/```\w*\n?/g, "").replace(/```/g, "").trim();
      if (code.length > 5) {
        patterns.push({ name: "Detection pattern", pattern: code.slice(0, 1000), language: lang });
      }
    }
  }

  return patterns.slice(0, 20);
}

/** Parse "Bypass Techniques" section */
function parseBypassTechniques(content: string): string[] {
  if (!content) return [];
  const techniques: string[] = [];

  // Extract bold sub-headings and code snippets
  const boldItems = content.match(/\*([^*\n]+)\*|`([^`\n]+)`/g) || [];
  for (const item of boldItems.slice(0, 20)) {
    const clean = item.replace(/[*`]/g, "").trim();
    if (clean.length > 5 && clean.length < 200) {
      techniques.push(clean);
    }
  }

  // Also extract code blocks as bypass examples
  const codeBlocks = content.match(/```[\w]*\n([\s\S]*?)```/g) || [];
  for (const cb of codeBlocks.slice(0, 5)) {
    const code = cb.replace(/```[\w]*\n?/g, "").replace(/```/g, "").trim();
    const lines = code.split("\n").filter((l) => l.trim() && !l.startsWith("--") && !l.startsWith("#"));
    for (const line of lines.slice(0, 3)) {
      if (line.trim().length > 3 && line.trim().length < 150) {
        techniques.push(line.trim());
      }
    }
  }

  return [...new Set(techniques)].slice(0, 25);
}

/** Parse "Gate 0 Validation" section */
function parseValidationGate(content: string): { question: string; criteria: string }[] {
  if (!content) return [];
  const gates: { question: string; criteria: string }[] = [];

  // Match bold numbered questions: **1. Question?**
  const questionBlocks = content.split(/\*\*\d+\.\s*/).filter(Boolean);
  for (const block of questionBlocks) {
    const qMatch = block.match(/^(.+?)\*\*\s*([\s\S]*)/);
    if (qMatch) {
      const question = qMatch[1].trim();
      const criteria = qMatch[2].trim().slice(0, 500);
      gates.push({ question, criteria });
    }
  }

  return gates.slice(0, 7);
}

/** Parse "Real Impact Examples" section */
function parseImpactExamples(content: string): { scenario: string; description: string; cveIds: string[] }[] {
  if (!content) return [];
  const examples: { scenario: string; description: string; cveIds: string[] }[] = [];

  // Split by bold scenario headers: **Scenario A — Title**
  const scenarioBlocks = content.split(/\*\*Scenario\s+\w+\s*[—–-]\s*/).filter(Boolean);
  for (const block of scenarioBlocks) {
    const titleMatch = block.match(/^(.+?)\*\*\s*([\s\S]*)/);
    if (titleMatch) {
      const scenario = titleMatch[1].trim();
      const description = titleMatch[2].trim().slice(0, 800);
      const cveIds = [...description.matchAll(/CVE-\d{4}-\d+/g)].map((m) => m[0]);
      examples.push({ scenario, description, cveIds: [...new Set(cveIds)] });
    }
  }

  // Also parse numbered disclosed reports (e.g., "9. **Name — CVE...**")
  if (examples.length === 0) {
    const numberedItems = content.split(/\n\d+\.\s+\*\*/).filter(Boolean);
    for (const item of numberedItems.slice(0, 8)) {
      const nameMatch = item.match(/^(.+?)\*\*\s*([\s\S]*)/);
      if (nameMatch) {
        const scenario = nameMatch[1].trim();
        const description = nameMatch[2].trim().slice(0, 800);
        const cveIds = [...item.matchAll(/CVE-\d{4}-\d+/g)].map((m) => m[0]);
        examples.push({ scenario, description, cveIds: [...new Set(cveIds)] });
      }
    }
  }

  return examples.slice(0, 12);
}

/** Parse "Related Skills & Chains" section */
function parseChains(content: string): { targetSkill: string; primitive: string }[] {
  if (!content) return [];
  const chains: { targetSkill: string; primitive: string }[] = [];

  // Match: - **`hunt-rce`** — description
  const chainMatches = content.matchAll(/[-*]\s+\*\*`([^`]+)`\*\*\s*[—–-]\s*(.+)/g);
  for (const match of chainMatches) {
    chains.push({
      targetSkill: match[1].trim(),
      primitive: match[2].trim().slice(0, 400),
    });
  }

  return chains.slice(0, 10);
}

/** Condense methodology section for AI prompts (max 2000 chars) */
function condenseMethodology(content: string): string {
  if (!content) return "";
  // Extract numbered steps
  const steps = content.match(/^\d+\.\s+\*\*(.+?)\*\*/gm) || [];
  if (steps.length > 0) {
    return steps.map((s) => s.replace(/^\d+\.\s+/, "").replace(/\*\*/g, "")).join("; ").slice(0, 2000);
  }
  // Fallback: first 2000 chars cleaned
  return content.replace(/```[\s\S]*?```/g, "[code]").trim().slice(0, 2000);
}

/** Detect frameworks from slug */
function detectFrameworks(slug: string): string[] {
  const frameworkMap: Record<string, string> = {
    "hunt-nextjs": "nextjs",
    "hunt-nodejs": "nodejs",
    "hunt-laravel": "laravel",
    "hunt-springboot": "springboot",
    "hunt-aspnet": "aspnet",
  };
  const fw = frameworkMap[slug];
  return fw ? [fw] : [];
}

/** Detect languages from slug and content */
function detectLanguages(slug: string, content: string): string[] {
  const langs = new Set<string>();

  // From slug
  const slugLangMap: Record<string, string> = {
    "hunt-nextjs": "javascript",
    "hunt-nodejs": "javascript",
    "hunt-laravel": "php",
    "hunt-springboot": "java",
    "hunt-aspnet": "csharp",
  };
  if (slugLangMap[slug]) langs.add(slugLangMap[slug]);

  // From content mentions
  const langPatterns: [RegExp, string][] = [
    [/javascript|node\.?js|express|npm/i, "javascript"],
    [/typescript|next\.?js/i, "typescript"],
    [/python|django|flask/i, "python"],
    [/java(?!script)|spring|maven/i, "java"],
    [/php|laravel|wordpress/i, "php"],
    [/ruby|rails/i, "ruby"],
    [/go(lang)?/i, "go"],
    [/csharp|\.net|asp\.net/i, "csharp"],
    [/kotlin/i, "kotlin"],
    [/scala/i, "scala"],
    [/swift/i, "swift"],
    [/rust/i, "rust"],
  ];

  for (const [pattern, lang] of langPatterns) {
    if (pattern.test(content)) langs.add(lang);
  }

  // Default: most web vuln classes apply broadly
  if (langs.size === 0) langs.add("all");

  return [...langs].slice(0, 8);
}

/** Determine category from slug */
function categorize(slug: string): string {
  if (slug.startsWith("hunt-")) return "web-app";
  if (["m365-entra-attack", "okta-attack", "cloud-iam-deep", "vmware-vcenter-attack", "enterprise-vpn-attack", "hunt-sharepoint", "hunt-aspnet", "hunt-ntlm-info", "apk-redteam-pipeline", "ios-redteam-pipeline"].includes(slug)) return "enterprise";
  if (["web2-recon", "offensive-osint", "osint-methodology", "recon-scope-triage", "hunt-subdomain"].includes(slug)) return "recon";
  if (["bb-methodology", "redteam-mindset", "bug-bounty", "bb-local-toolkit"].includes(slug)) return "methodology";
  if (["bugcrowd-reporting", "evidence-hygiene", "mid-engagement-ir-detection", "redteam-report-template", "report-writing", "triage-validation"].includes(slug)) return "reporting";
  if (["security-arsenal", "hunt-dispatch", "supply-chain-attack-recon", "meme-coin-audit", "web3-audit"].includes(slug)) return "specialized";
  return "web-app";
}

/**
 * Main parser: takes raw SKILL.md content and slug, returns structured ParsedSkill
 */
export function parseSkillMarkdown(raw: string, slug: string): ParsedSkill {
  const { frontmatter, body } = parseFrontmatter(raw);
  const sections = splitSections(body);

  // Find sections by fuzzy heading match
  const findSection = (keywords: string[]): string => {
    for (const [heading, content] of sections) {
      const lower = heading.toLowerCase();
      if (keywords.some((kw) => lower.includes(kw.toLowerCase()))) {
        return content;
      }
    }
    return "";
  };

  const rootCausesContent = findSection(["Common Root Causes", "Root Cause"]);
  const attackSignalsContent = findSection(["Attack Surface Signals", "Attack Surface"]);
  const detectionContent = findSection(["Payload & Detection", "Detection Patterns", "Payload"]);
  const bypassContent = findSection(["Bypass Techniques", "Bypass", "WAF Bypass"]);
  const validationContent = findSection(["Gate 0 Validation", "Validation", "Gate 0"]);
  const impactContent = findSection(["Real Impact Examples", "Impact Examples", "Disclosed Report"]);
  const chainsContent = findSection(["Related Skills & Chains", "Related Skills", "Chains"]);
  const methodologyContent = findSection(["Step-by-Step Hunting Methodology", "Methodology", "Hunting Methodology"]);

  // Build display name from slug
  const displayName = frontmatter.name ||
    slug.replace(/^hunt-/, "").replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  return {
    slug,
    name: displayName,
    category: categorize(slug),
    description: frontmatter.description || "",
    reportCount: frontmatter.reportCount,
    sources: frontmatter.sources,
    rootCauses: parseRootCauses(rootCausesContent),
    attackSignals: parseAttackSignals(attackSignalsContent),
    detectionPatterns: parseDetectionPatterns(detectionContent),
    bypassTechniques: parseBypassTechniques(bypassContent),
    validationGate: parseValidationGate(validationContent),
    impactExamples: parseImpactExamples(impactContent),
    chains: parseChains(chainsContent),
    methodology: condenseMethodology(methodologyContent),
    frameworks: detectFrameworks(slug),
    languages: detectLanguages(slug, body),
  };
}

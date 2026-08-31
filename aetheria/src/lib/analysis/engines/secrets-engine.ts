/**
 * Secrets Detection Engine
 * Detects hardcoded credentials, API keys, tokens, and private keys
 * using regex patterns + Shannon entropy analysis.
 *
 * All patterns are loaded from the database (SecretPattern model).
 * Patterns sourced from: GitHub secret scanning, TruffleHog, detect-secrets, AWS docs.
 */

export interface SecretFinding {
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
  secretType: string;
  detectionMethod: "SECRET";
}

export interface DbSecretPattern {
  ruleId: string;
  name: string;
  regex: string;
  severity: string;
  cwe: string;
  description: string;
}

// ==================== SHANNON ENTROPY ====================
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Strings that look random but are NOT secrets
const ENTROPY_EXCLUSIONS = [
  /^[0-9a-f]{32,64}$/i, // MD5/SHA hashes
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUIDs
  /^https?:\/\//, // URLs
  /^[A-Za-z0-9+/]{40,}={0,2}$/, // Base64 (could be data, not secret)
  /^\d+$/, // Pure numbers
  /^[a-f0-9]+$/i, // Hex strings (likely hashes)
  /^sha(256|384|512)-/, // npm/yarn integrity hashes
  /^sha1-/, // npm integrity sha1
];

// Files that should NEVER be scanned for secrets (lock files, minified, maps)
const EXCLUDED_FILES = /\.(lock|min\.js|min\.css|map|bundle\.js|chunk\.js)$/i;
const EXCLUDED_FILENAMES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|go\.sum|poetry\.lock|Pipfile\.lock|cargo\.lock|nuget\.config|\.npmrc)$/i;

// Line context that indicates a non-secret high-entropy value
const ENTROPY_CONTEXT_EXCLUSIONS = /integrity|resolved|checksum|digest|etag|content-hash|sha(256|384|512)|hash|fingerprint|publicKey|modulus|customAlphabet|nanoid|alphabet/i;

// ==================== MAIN ENGINE ====================
export function runSecretsDetection(fileContent: string, filePath: string, patterns: DbSecretPattern[]): SecretFinding[] {
  const lines = fileContent.split("\n");
  const findings: SecretFinding[] = [];
  const seenLines = new Set<string>();

  // Skip binary/minified files
  if (filePath.match(/\.(png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot|svg|mp4|mp3|zip|tar|gz|bin|exe|dll|so|dylib)$/i)) {
    return [];
  }

  // Skip lock files, minified bundles, source maps
  if (EXCLUDED_FILES.test(filePath) || EXCLUDED_FILENAMES.test(filePath)) {
    return [];
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Skip comments that mention "example" or "placeholder"
    if (line.match(/(example|placeholder|your[_-]?key|xxx|changeme|todo|fixme)/i)) {
      continue;
    }

    // Pattern-based detection (patterns loaded from DB)
    for (const pattern of patterns) {
      try {
        // Convert (?i) prefix to JS regex 'i' flag
        let regexStr = pattern.regex;
        let flags = "";
        if (regexStr.startsWith("(?i)")) {
          regexStr = regexStr.slice(4);
          flags = "i";
        }
        const regex = new RegExp(regexStr, flags);
        if (regex.test(line)) {
          const key = `${pattern.ruleId}:${lineNum}`;
          if (seenLines.has(key)) continue;
          seenLines.add(key);

          // Mask the secret in the snippet
          const maskedLine = maskSecret(line);

          findings.push({
            cwe: pattern.cwe,
            category: "Hardcoded Secret",
            severity: pattern.severity as SecretFinding["severity"],
            owasp2021: "A07:2021",
            title: `${pattern.name} in ${filePath.split("/").pop()}`,
            description: `${pattern.description} at line ${lineNum}. ${pattern.cwe}: Use of hard-coded credentials. Secrets should be stored in environment variables or a secrets manager.`,
            filePath,
            lineStart: lineNum,
            lineEnd: lineNum,
            codeSnippet: maskedLine,
            confidence: 92,
            secretType: pattern.name,
            detectionMethod: "SECRET",
          });
        }
      } catch {
        // Invalid regex, skip
      }
    }

    // Entropy-based detection for long strings
    const stringMatches = line.match(/['"]([A-Za-z0-9+/=_\-]{20,})['"]/g);
    if (stringMatches) {
      // Skip lines that are clearly integrity/hash context
      if (ENTROPY_CONTEXT_EXCLUSIONS.test(line)) continue;

      for (const match of stringMatches) {
        const value = match.slice(1, -1); // Remove quotes
        if (value.length < 20 || value.length > 200) continue;

        // Check exclusions
        if (ENTROPY_EXCLUSIONS.some((ex) => ex.test(value))) continue;

        const entropy = shannonEntropy(value);
        if (entropy > 4.5) {
          const key = `entropy:${lineNum}`;
          if (seenLines.has(key)) continue;
          seenLines.add(key);

          findings.push({
            cwe: "CWE-798",
            category: "High-Entropy Secret",
            severity: "MEDIUM",
            owasp2021: "A07:2021",
            title: `High-entropy string (possible secret) in ${filePath.split("/").pop()}`,
            description: `String with Shannon entropy ${entropy.toFixed(2)} bits/char detected at line ${lineNum}. This may be a hardcoded secret, API key, or token. Verify and move to environment variables if sensitive.`,
            filePath,
            lineStart: lineNum,
            lineEnd: lineNum,
            codeSnippet: maskSecret(line),
            confidence: 65,
            secretType: "High-Entropy String",
            detectionMethod: "SECRET",
          });
        }
      }
    }
  }

  return findings;
}

function maskSecret(line: string): string {
  // Mask potential secrets in output (show first 4 + last 4 chars)
  return line.replace(/(['"])([A-Za-z0-9+/=_\-]{12,})\1/g, (_match, quote, secret) => {
    if (secret.length <= 8) return `${quote}${secret}${quote}`;
    return `${quote}${secret.slice(0, 4)}${"*".repeat(Math.min(secret.length - 8, 20))}${secret.slice(-4)}${quote}`;
  });
}

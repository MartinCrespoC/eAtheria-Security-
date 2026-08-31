/**
 * CWE Mapper for BugHunter Skills
 * Maps each skill slug to its relevant CWE identifiers.
 * Primary = direct vulnerability class, Secondary = related/subclass, Chain = escalation target.
 */

export interface CweMapping {
  cweId: string;
  relevance: "PRIMARY" | "SECONDARY" | "CHAIN";
}

/**
 * Curated skill → CWE mapping based on the 24 core vulnerability classes
 * and framework-specific skills from Claude-BugHunter.
 */
export const SKILL_CWE_MAP: Record<string, CweMapping[]> = {
  // === Web Application Hunting (57 hunt-* skills) ===
  "hunt-sqli": [
    { cweId: "CWE-89", relevance: "PRIMARY" },
    { cweId: "CWE-564", relevance: "SECONDARY" }, // SQL Injection: Hibernate
    { cweId: "CWE-943", relevance: "SECONDARY" }, // NoSQL injection
  ],
  "hunt-nosqli": [
    { cweId: "CWE-943", relevance: "PRIMARY" }, // NoSQL Injection
    { cweId: "CWE-89", relevance: "SECONDARY" },
  ],
  "hunt-xss": [
    { cweId: "CWE-79", relevance: "PRIMARY" },
    { cweId: "CWE-80", relevance: "SECONDARY" }, // Basic XSS
    { cweId: "CWE-87", relevance: "SECONDARY" }, // XSS in Alternate Syntax
  ],
  "hunt-dom": [
    { cweId: "CWE-79", relevance: "PRIMARY" },
    { cweId: "CWE-1321", relevance: "SECONDARY" }, // DOM Clobbering
    { cweId: "CWE-345", relevance: "SECONDARY" }, // PostMessage origin
  ],
  "hunt-html-injection": [
    { cweId: "CWE-80", relevance: "PRIMARY" },
    { cweId: "CWE-79", relevance: "SECONDARY" },
  ],
  "hunt-ssrf": [
    { cweId: "CWE-918", relevance: "PRIMARY" },
    { cweId: "CWE-441", relevance: "SECONDARY" }, // Unintended Proxy
  ],
  "hunt-idor": [
    { cweId: "CWE-639", relevance: "PRIMARY" }, // Authorization Bypass Through User-Controlled Key
    { cweId: "CWE-862", relevance: "SECONDARY" }, // Missing Authorization
    { cweId: "CWE-284", relevance: "SECONDARY" }, // Improper Access Control
  ],
  "hunt-rce": [
    { cweId: "CWE-94", relevance: "PRIMARY" }, // Code Injection
    { cweId: "CWE-78", relevance: "PRIMARY" }, // OS Command Injection
    { cweId: "CWE-502", relevance: "SECONDARY" }, // Deserialization → RCE
  ],
  "hunt-lfi": [
    { cweId: "CWE-22", relevance: "PRIMARY" }, // Path Traversal
    { cweId: "CWE-98", relevance: "SECONDARY" }, // Remote File Inclusion
    { cweId: "CWE-73", relevance: "SECONDARY" }, // External Control of File Name
  ],
  "hunt-file-upload": [
    { cweId: "CWE-434", relevance: "PRIMARY" }, // Unrestricted File Upload
    { cweId: "CWE-22", relevance: "SECONDARY" }, // Path traversal via filename
    { cweId: "CWE-611", relevance: "CHAIN" }, // XXE via DOCX
  ],
  "hunt-xxe": [
    { cweId: "CWE-611", relevance: "PRIMARY" },
    { cweId: "CWE-776", relevance: "SECONDARY" }, // XML Entity Expansion (Billion Laughs)
  ],
  "hunt-ssti": [
    { cweId: "CWE-1336", relevance: "PRIMARY" }, // Server-Side Template Injection
    { cweId: "CWE-94", relevance: "SECONDARY" }, // Code Injection
  ],
  "hunt-csrf": [
    { cweId: "CWE-352", relevance: "PRIMARY" },
  ],
  "hunt-cors": [
    { cweId: "CWE-942", relevance: "PRIMARY" }, // Permissive CORS
    { cweId: "CWE-345", relevance: "SECONDARY" }, // Insufficient Verification of Data Authenticity
  ],
  "hunt-open-redirect": [
    { cweId: "CWE-601", relevance: "PRIMARY" },
    { cweId: "CWE-20", relevance: "SECONDARY" }, // Improper Input Validation
  ],
  "hunt-graphql": [
    { cweId: "CWE-200", relevance: "PRIMARY" }, // Introspection exposure
    { cweId: "CWE-862", relevance: "SECONDARY" }, // Missing auth on resolvers
    { cweId: "CWE-400", relevance: "SECONDARY" }, // Query depth DoS
  ],
  "hunt-grpc": [
    { cweId: "CWE-306", relevance: "PRIMARY" }, // Missing Authentication
    { cweId: "CWE-200", relevance: "SECONDARY" }, // Reflection exposure
  ],
  "hunt-websocket": [
    { cweId: "CWE-345", relevance: "PRIMARY" }, // Insufficient Origin Verification
    { cweId: "CWE-862", relevance: "SECONDARY" }, // Missing per-message auth
  ],
  "hunt-api-misconfig": [
    { cweId: "CWE-915", relevance: "PRIMARY" }, // Mass Assignment
    { cweId: "CWE-1321", relevance: "SECONDARY" }, // Prototype Pollution
    { cweId: "CWE-352", relevance: "SECONDARY" }, // HTTP Verb Tampering
  ],
  "hunt-host-header": [
    { cweId: "CWE-644", relevance: "PRIMARY" }, // Improper Neutralization of HTTP Headers
    { cweId: "CWE-918", relevance: "CHAIN" }, // SSRF via Host
  ],
  "hunt-deserialization": [
    { cweId: "CWE-502", relevance: "PRIMARY" },
    { cweId: "CWE-94", relevance: "CHAIN" }, // RCE via deserialization
  ],
  "hunt-race-condition": [
    { cweId: "CWE-362", relevance: "PRIMARY" },
    { cweId: "CWE-367", relevance: "SECONDARY" }, // TOCTOU
  ],
  "hunt-http-smuggling": [
    { cweId: "CWE-444", relevance: "PRIMARY" },
    { cweId: "CWE-436", relevance: "SECONDARY" }, // Interpretation Conflict
  ],
  "hunt-cache-poison": [
    { cweId: "CWE-444", relevance: "PRIMARY" },
    { cweId: "CWE-942", relevance: "SECONDARY" },
    { cweId: "CWE-644", relevance: "SECONDARY" },
  ],
  "hunt-auth-bypass": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-863", relevance: "SECONDARY" }, // Incorrect Authorization
  ],
  "hunt-session": [
    { cweId: "CWE-614", relevance: "PRIMARY" }, // Sensitive Cookie Without Secure
    { cweId: "CWE-384", relevance: "PRIMARY" }, // Session Fixation
    { cweId: "CWE-613", relevance: "SECONDARY" }, // Insufficient Session Expiration
  ],
  "hunt-oauth": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-601", relevance: "SECONDARY" }, // redirect_uri open redirect
    { cweId: "CWE-345", relevance: "SECONDARY" }, // Insufficient state verification
  ],
  "hunt-saml": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-347", relevance: "SECONDARY" }, // Improper Signature Verification
  ],
  "hunt-jwt-crypto": [
    { cweId: "CWE-347", relevance: "PRIMARY" }, // Improper Signature Verification
    { cweId: "CWE-327", relevance: "SECONDARY" }, // Broken Crypto (alg:none)
    { cweId: "CWE-287", relevance: "CHAIN" },
  ],
  "hunt-mfa-bypass": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-304", relevance: "SECONDARY" }, // Missing Critical Step in Auth
  ],
  "hunt-ato": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-640", relevance: "SECONDARY" }, // Weak Password Recovery
    { cweId: "CWE-384", relevance: "SECONDARY" },
  ],
  "hunt-forgot-password": [
    { cweId: "CWE-640", relevance: "PRIMARY" },
    { cweId: "CWE-200", relevance: "SECONDARY" }, // Username enumeration
    { cweId: "CWE-330", relevance: "SECONDARY" }, // Predictable token
  ],
  "hunt-brute-force": [
    { cweId: "CWE-307", relevance: "PRIMARY" }, // Improper Restriction of Excessive Auth Attempts
    { cweId: "CWE-200", relevance: "SECONDARY" }, // Enumeration
  ],
  "hunt-captcha-bypass": [
    { cweId: "CWE-804", relevance: "PRIMARY" }, // Guessable CAPTCHA
    { cweId: "CWE-345", relevance: "SECONDARY" },
  ],
  "hunt-business-logic": [
    { cweId: "CWE-840", relevance: "PRIMARY" }, // Business Logic Errors
    { cweId: "CWE-841", relevance: "SECONDARY" }, // Improper Enforcement of Behavioral Workflow
  ],
  "hunt-clickjacking": [
    { cweId: "CWE-1021", relevance: "PRIMARY" },
  ],
  "hunt-cloud-misconfig": [
    { cweId: "CWE-284", relevance: "PRIMARY" },
    { cweId: "CWE-200", relevance: "SECONDARY" }, // Public S3 exposure
    { cweId: "CWE-732", relevance: "SECONDARY" }, // Incorrect Permission Assignment
  ],
  "hunt-k8s": [
    { cweId: "CWE-284", relevance: "PRIMARY" },
    { cweId: "CWE-306", relevance: "SECONDARY" }, // Anonymous API access
    { cweId: "CWE-250", relevance: "SECONDARY" }, // SA token abuse
  ],
  "hunt-cicd": [
    { cweId: "CWE-94", relevance: "PRIMARY" }, // Workflow injection
    { cweId: "CWE-284", relevance: "SECONDARY" }, // OIDC trust abuse
    { cweId: "CWE-502", relevance: "SECONDARY" },
  ],
  "hunt-source-leak": [
    { cweId: "CWE-200", relevance: "PRIMARY" },
    { cweId: "CWE-540", relevance: "SECONDARY" }, // Source Code Exposure
    { cweId: "CWE-526", relevance: "SECONDARY" }, // .env/.git exposure
  ],
  "hunt-spa-api": [
    { cweId: "CWE-306", relevance: "PRIMARY" },
    { cweId: "CWE-862", relevance: "SECONDARY" },
  ],
  "hunt-shadow-api": [
    { cweId: "CWE-912", relevance: "PRIMARY" }, // Hidden Functionality
    { cweId: "CWE-306", relevance: "SECONDARY" },
  ],
  "hunt-ldap": [
    { cweId: "CWE-90", relevance: "PRIMARY" }, // LDAP Injection
    { cweId: "CWE-643", relevance: "SECONDARY" }, // XPath Injection
  ],
  "hunt-llm-ai": [
    { cweId: "CWE-75", relevance: "PRIMARY" }, // Prompt Injection (special)
    { cweId: "CWE-200", relevance: "SECONDARY" }, // Exfiltration
  ],
  "hunt-rag-vector": [
    { cweId: "CWE-75", relevance: "PRIMARY" },
    { cweId: "CWE-915", relevance: "SECONDARY" }, // Corpus poisoning
  ],
  "hunt-subdomain": [
    { cweId: "CWE-350", relevance: "PRIMARY" }, // Reliance on Reverse DNS
    { cweId: "CWE-284", relevance: "SECONDARY" },
  ],
  "hunt-tls-network": [
    { cweId: "CWE-319", relevance: "PRIMARY" }, // Cleartext Transmission
    { cweId: "CWE-326", relevance: "SECONDARY" }, // Weak Encryption
    { cweId: "CWE-295", relevance: "SECONDARY" }, // Improper Cert Validation
  ],
  "hunt-exceptional-conditions": [
    { cweId: "CWE-755", relevance: "PRIMARY" }, // Improper Handling of Exceptional Conditions
    { cweId: "CWE-209", relevance: "SECONDARY" }, // Error Message Info Leak
  ],
  "hunt-misc": [
    { cweId: "CWE-20", relevance: "PRIMARY" }, // Improper Input Validation (catch-all)
  ],

  // === Framework-Specific ===
  "hunt-nextjs": [
    { cweId: "CWE-94", relevance: "PRIMARY" }, // Server Actions RCE
    { cweId: "CWE-862", relevance: "PRIMARY" }, // Middleware auth bypass
    { cweId: "CWE-918", relevance: "SECONDARY" }, // Image Optimization SSRF
    { cweId: "CWE-444", relevance: "SECONDARY" }, // ISR cache poisoning
  ],
  "hunt-nodejs": [
    { cweId: "CWE-1321", relevance: "PRIMARY" }, // Prototype Pollution
    { cweId: "CWE-78", relevance: "SECONDARY" }, // child_process injection
    { cweId: "CWE-94", relevance: "SECONDARY" }, // eval injection
    { cweId: "CWE-22", relevance: "SECONDARY" }, // path traversal
  ],
  "hunt-laravel": [
    { cweId: "CWE-200", relevance: "PRIMARY" }, // Debug mode leakage
    { cweId: "CWE-94", relevance: "SECONDARY" }, // Ignition RCE
    { cweId: "CWE-862", relevance: "SECONDARY" }, // Telescope unauthorized
  ],
  "hunt-springboot": [
    { cweId: "CWE-200", relevance: "PRIMARY" }, // Actuator exposure
    { cweId: "CWE-94", relevance: "SECONDARY" }, // SpEL injection
    { cweId: "CWE-917", relevance: "SECONDARY" }, // Expression Language Injection
  ],
  "hunt-aspnet": [
    { cweId: "CWE-502", relevance: "PRIMARY" }, // ViewState deserialization
    { cweId: "CWE-200", relevance: "SECONDARY" }, // trace.axd disclosure
  ],

  // === Enterprise Platform ===
  "m365-entra-attack": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-862", relevance: "SECONDARY" },
  ],
  "okta-attack": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-307", relevance: "SECONDARY" },
  ],
  "cloud-iam-deep": [
    { cweId: "CWE-284", relevance: "PRIMARY" },
    { cweId: "CWE-269", relevance: "SECONDARY" }, // Improper Privilege Management
  ],
  "vmware-vcenter-attack": [
    { cweId: "CWE-94", relevance: "PRIMARY" },
    { cweId: "CWE-434", relevance: "SECONDARY" },
  ],
  "enterprise-vpn-attack": [
    { cweId: "CWE-94", relevance: "PRIMARY" },
    { cweId: "CWE-287", relevance: "SECONDARY" },
  ],
  "hunt-sharepoint": [
    { cweId: "CWE-287", relevance: "PRIMARY" },
    { cweId: "CWE-94", relevance: "SECONDARY" },
  ],
  "hunt-ntlm-info": [
    { cweId: "CWE-200", relevance: "PRIMARY" },
  ],
  "supply-chain-attack-recon": [
    { cweId: "CWE-829", relevance: "PRIMARY" }, // Inclusion of Functionality from Untrusted Sphere
    { cweId: "CWE-494", relevance: "SECONDARY" }, // Download of Code Without Integrity Check
  ],

  // === Recon & Methodology (minimal CWE mapping) ===
  "web2-recon": [{ cweId: "CWE-200", relevance: "SECONDARY" }],
  "offensive-osint": [{ cweId: "CWE-200", relevance: "SECONDARY" }],
  "security-arsenal": [],
  "bb-methodology": [],
  "redteam-mindset": [],
  "triage-validation": [],
  "report-writing": [],
  "evidence-hygiene": [],
};

/**
 * Get CWE mappings for a skill slug.
 * Falls back to empty array if not in the curated map.
 */
export function getCweMappingsForSkill(slug: string): CweMapping[] {
  return SKILL_CWE_MAP[slug] || [];
}

/**
 * Infer CWE IDs from skill description text (fallback for unmapped skills).
 * Uses keyword matching against common vulnerability terms.
 */
export function inferCwesFromDescription(description: string): CweMapping[] {
  const keywordCweMap: [RegExp, string][] = [
    [/sql\s*injection|sqli/i, "CWE-89"],
    [/nosql|mongodb.*inject/i, "CWE-943"],
    [/xss|cross.site.script/i, "CWE-79"],
    [/ssrf|server.side.request/i, "CWE-918"],
    [/idor|insecure.direct/i, "CWE-639"],
    [/rce|remote.code.exec|command.inject/i, "CWE-94"],
    [/path.travers|lfi|file.inclus/i, "CWE-22"],
    [/xxe|xml.external/i, "CWE-611"],
    [/ssti|template.inject/i, "CWE-1336"],
    [/csrf|cross.site.request/i, "CWE-352"],
    [/cors|origin/i, "CWE-942"],
    [/redirect/i, "CWE-601"],
    [/deserializ/i, "CWE-502"],
    [/race.condition|toctou/i, "CWE-362"],
    [/smuggl/i, "CWE-444"],
    [/auth.*bypass|authentication/i, "CWE-287"],
    [/session/i, "CWE-384"],
    [/oauth/i, "CWE-287"],
    [/jwt|json.web.token/i, "CWE-347"],
    [/upload|file.*upload/i, "CWE-434"],
    [/info.*disclos|exposure|leak/i, "CWE-200"],
    [/privilege|access.control/i, "CWE-284"],
    [/crypto|encrypt/i, "CWE-327"],
    [/secret|credential|hardcod/i, "CWE-798"],
  ];

  const results: CweMapping[] = [];
  for (const [pattern, cwe] of keywordCweMap) {
    if (pattern.test(description)) {
      results.push({ cweId: cwe, relevance: "SECONDARY" });
    }
  }

  return results.slice(0, 5);
}

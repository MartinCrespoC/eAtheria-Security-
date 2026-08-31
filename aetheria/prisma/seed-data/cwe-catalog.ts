export const CWE_CATALOG = [
  {
    cweId: "CWE-89",
    name: "SQL Injection",
    description:
      "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
    severity: "CRITICAL" as const,
    category: "Injection",
    owaspTop10_2021: "A03:2021",
    owaspTop10_2017: "A01:2017",
    owaspAsvs: "V5.3.4",
    pciDss: "6.5.1",
    languages: ["javascript", "typescript", "python", "java", "php", "csharp", "ruby", "go"],
    remediation:
      "Use parameterized queries, prepared statements, or ORMs. Never concatenate user input directly into SQL strings.",
    references: [
      "https://owasp.org/www-community/attacks/SQL_Injection",
      "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ],
  },
  {
    cweId: "CWE-79",
    name: "Cross-Site Scripting (XSS)",
    description:
      "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
    severity: "HIGH" as const,
    category: "Injection",
    owaspTop10_2021: "A03:2021",
    owaspTop10_2017: "A07:2017",
    owaspAsvs: "V5.3.3",
    languages: ["javascript", "typescript", "python", "java", "php"],
    remediation:
      "Encode output, use Content Security Policy (CSP), validate input, use templating engines with auto-escaping.",
    references: ["https://owasp.org/www-community/attacks/xss/"],
  },
  {
    cweId: "CWE-78",
    name: "OS Command Injection",
    description:
      "The software constructs all or part of an OS command using externally-influenced input but does not neutralize special elements.",
    severity: "CRITICAL" as const,
    category: "Injection",
    owaspTop10_2021: "A03:2021",
    languages: ["python", "java", "javascript", "php", "ruby", "go", "csharp"],
    remediation:
      "Avoid OS commands with user input. Use language-specific APIs. If necessary, use allowlists and proper escaping.",
    references: ["https://owasp.org/www-community/attacks/Command_Injection"],
  },
  {
    cweId: "CWE-798",
    name: "Use of Hard-coded Credentials",
    description:
      "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
    severity: "CRITICAL" as const,
    category: "Authentication",
    owaspTop10_2021: "A07:2021",
    owaspAsvs: "V2.10.4",
    pciDss: "8.2.1",
    languages: ["all"],
    remediation:
      "Store credentials in environment variables, secret managers, or encrypted configuration files.",
    references: ["https://cwe.mitre.org/data/definitions/798.html"],
  },
  {
    cweId: "CWE-287",
    name: "Improper Authentication",
    description:
      "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
    severity: "CRITICAL" as const,
    category: "Authentication",
    owaspTop10_2021: "A07:2021",
    languages: ["all"],
    remediation:
      "Implement strong authentication mechanisms including MFA, session management, and password policies.",
    references: [],
  },
  {
    cweId: "CWE-306",
    name: "Missing Authentication for Critical Function",
    description:
      "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
    severity: "CRITICAL" as const,
    category: "Authentication",
    owaspTop10_2021: "A07:2021",
    languages: ["all"],
    remediation: "Implement authentication on all sensitive endpoints.",
    references: [],
  },
  {
    cweId: "CWE-862",
    name: "Missing Authorization",
    description:
      "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
    severity: "HIGH" as const,
    category: "Authorization",
    owaspTop10_2021: "A01:2021",
    languages: ["all"],
    remediation:
      "Implement role-based access control (RBAC) and verify authorization on every request.",
    references: [],
  },
  {
    cweId: "CWE-327",
    name: "Use of Broken or Risky Cryptographic Algorithm",
    description:
      "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
    severity: "MEDIUM" as const,
    category: "Cryptography",
    owaspTop10_2021: "A02:2021",
    languages: ["all"],
    remediation:
      "Use strong, modern algorithms: AES-256, SHA-256+, RSA-2048+. Avoid MD5, SHA1, DES, 3DES.",
    references: [],
  },
  {
    cweId: "CWE-328",
    name: "Use of Weak Hash",
    description:
      "The product uses an algorithm that produces a digest (output value) that does not meet security expectations for a hash function.",
    severity: "MEDIUM" as const,
    category: "Cryptography",
    owaspTop10_2021: "A02:2021",
    languages: ["all"],
    remediation:
      "Use bcrypt, scrypt, or Argon2 for password hashing. Use SHA-256+ for general hashing.",
    references: [],
  },
  {
    cweId: "CWE-200",
    name: "Exposure of Sensitive Information",
    description:
      "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
    severity: "HIGH" as const,
    category: "Data Exposure",
    owaspTop10_2021: "A01:2021",
    languages: ["all"],
    remediation:
      "Review error messages, logs, and API responses. Do not expose stack traces or internal details.",
    references: [],
  },
  {
    cweId: "CWE-312",
    name: "Cleartext Storage of Sensitive Information",
    description:
      "The application stores sensitive information in cleartext in a resource that might be accessible to another control sphere.",
    severity: "HIGH" as const,
    category: "Data Exposure",
    owaspTop10_2021: "A02:2021",
    languages: ["all"],
    remediation:
      "Encrypt sensitive data at rest using strong encryption (AES-256).",
    references: [],
  },
  {
    cweId: "CWE-319",
    name: "Cleartext Transmission of Sensitive Information",
    description:
      "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
    severity: "HIGH" as const,
    category: "Data Exposure",
    owaspTop10_2021: "A02:2021",
    languages: ["all"],
    remediation: "Always use HTTPS/TLS 1.2+ for sensitive data transmission.",
    references: [],
  },
  {
    cweId: "CWE-787",
    name: "Out-of-bounds Write",
    description:
      "The software writes data past the end, or before the beginning, of the intended buffer.",
    severity: "CRITICAL" as const,
    category: "Memory Safety",
    languages: ["c", "cpp", "rust"],
    remediation:
      "Use safe memory management, bounds checking, and modern languages with memory safety guarantees.",
    references: [],
  },
  {
    cweId: "CWE-125",
    name: "Out-of-bounds Read",
    description:
      "The software reads data past the end, or before the beginning, of the intended buffer.",
    severity: "HIGH" as const,
    category: "Memory Safety",
    languages: ["c", "cpp"],
    remediation: "Validate buffer sizes and indices before accessing memory.",
    references: [],
  },
  {
    cweId: "CWE-416",
    name: "Use After Free",
    description:
      "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
    severity: "CRITICAL" as const,
    category: "Memory Safety",
    languages: ["c", "cpp"],
    remediation: "Set pointers to NULL after freeing. Use smart pointers in C++.",
    references: [],
  },
  {
    cweId: "CWE-1104",
    name: "Use of Unmaintained Third Party Components",
    description:
      "The product relies on third-party components that are not actively supported or maintained.",
    severity: "HIGH" as const,
    category: "Dependencies",
    owaspTop10_2021: "A06:2021",
    languages: ["all"],
    remediation:
      "Regularly update dependencies. Use tools like Dependabot, Snyk, or OSV.",
    references: [],
  },
  {
    cweId: "CWE-829",
    name: "Inclusion of Functionality from Untrusted Control Sphere",
    description:
      "The software imports, requires, or includes executable functionality from a source that is outside the intended control sphere.",
    severity: "CRITICAL" as const,
    category: "Supply Chain",
    owaspTop10_2021: "A08:2021",
    languages: ["all"],
    remediation:
      "Verify package integrity, use lockfiles, avoid typosquatting, use private registries.",
    references: [],
  },
  {
    cweId: "CWE-20",
    name: "Improper Input Validation",
    description:
      "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
    severity: "HIGH" as const,
    category: "Input Validation",
    owaspTop10_2021: "A03:2021",
    languages: ["all"],
    remediation: "Validate all inputs using allowlists, type checks, and length limits.",
    references: [],
  },
  {
    cweId: "CWE-22",
    name: "Path Traversal",
    description:
      "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory.",
    severity: "HIGH" as const,
    category: "Injection",
    owaspTop10_2021: "A01:2021",
    languages: ["all"],
    remediation:
      "Validate and sanitize file paths. Use allowlists. Reject paths containing '..'.",
    references: [],
  },
  {
    cweId: "CWE-352",
    name: "Cross-Site Request Forgery (CSRF)",
    description:
      "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
    severity: "HIGH" as const,
    category: "Authorization",
    owaspTop10_2021: "A01:2021",
    languages: ["javascript", "typescript", "python", "java", "php", "ruby"],
    remediation:
      "Implement CSRF tokens, use SameSite cookies, verify Origin/Referer headers.",
    references: [],
  },
  {
    cweId: "CWE-434",
    name: "Unrestricted Upload of File with Dangerous Type",
    description:
      "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
    severity: "CRITICAL" as const,
    category: "File Upload",
    owaspTop10_2021: "A04:2021",
    languages: ["all"],
    remediation:
      "Validate file types, restrict extensions, scan for malware, store outside web root.",
    references: [],
  },
  {
    cweId: "CWE-918",
    name: "Server-Side Request Forgery (SSRF)",
    description:
      "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
    severity: "CRITICAL" as const,
    category: "Injection",
    owaspTop10_2021: "A10:2021",
    languages: ["all"],
    remediation:
      "Validate URLs, use allowlists for destinations, block internal IP ranges.",
    references: [],
  },
  {
    cweId: "CWE-502",
    name: "Deserialization of Untrusted Data",
    description:
      "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
    severity: "CRITICAL" as const,
    category: "Injection",
    owaspTop10_2021: "A08:2021",
    languages: ["java", "python", "javascript", "ruby", "php", "csharp"],
    remediation:
      "Avoid deserializing untrusted data. Use signed, encrypted payloads. Use safer formats like JSON with schema validation.",
    references: [],
  },
  {
    cweId: "CWE-611",
    name: "XML External Entities (XXE)",
    description:
      "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
    severity: "HIGH" as const,
    category: "Injection",
    owaspTop10_2021: "A05:2021",
    languages: ["java", "python", "php", "dotnet"],
    remediation: "Disable XML external entity processing in XML parsers.",
    references: [],
  },
  {
    cweId: "CWE-601",
    name: "Open Redirect",
    description:
      "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.",
    severity: "MEDIUM" as const,
    category: "Redirect",
    languages: ["all"],
    remediation: "Use allowlists for redirect destinations. Never trust user input.",
    references: [],
  },
  // === INJECTION (additional) ===
  { cweId: "CWE-77", name: "Command Injection", description: "Improper neutralization of special elements used in a command.", severity: "CRITICAL" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Use parameterized commands; avoid shell execution with user input.", references: [] },
  { cweId: "CWE-90", name: "LDAP Injection", description: "Software constructs LDAP queries from user input without proper sanitization.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["java", "csharp", "python", "php"], remediation: "Escape special LDAP characters; use parameterized LDAP queries.", references: [] },
  { cweId: "CWE-91", name: "XML Injection (Blind XPath)", description: "Improper neutralization of input used in XML or XPath queries.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["java", "python", "php"], remediation: "Use parameterized XPath queries; validate XML input.", references: [] },
  { cweId: "CWE-94", name: "Code Injection", description: "Improper control of generation of code allowing execution of arbitrary code.", severity: "CRITICAL" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["javascript", "python", "php", "ruby"], remediation: "Never use eval() with user input; use sandboxed environments.", references: [] },
  { cweId: "CWE-95", name: "Eval Injection", description: "Use of eval-type functions with user-controlled strings.", severity: "CRITICAL" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["javascript", "python", "ruby", "php"], remediation: "Remove eval(); use AST parsing or sandboxing.", references: [] },
  { cweId: "CWE-96", name: "Improper Neutralization of Directives in Statically Saved Code", description: "Server-side template injection or static file modification.", severity: "HIGH" as const, category: "Injection", languages: ["python", "java", "javascript"], remediation: "Use auto-escaping template engines; never render user input as template code.", references: [] },
  { cweId: "CWE-113", name: "HTTP Response Splitting", description: "Software includes user input in HTTP headers without neutralizing CR/LF.", severity: "MEDIUM" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Strip CR/LF characters from header values.", references: [] },
  { cweId: "CWE-917", name: "Expression Language Injection", description: "Software uses user input in expression language statements.", severity: "CRITICAL" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["java"], remediation: "Avoid EL with user input; use strict input validation.", references: [] },
  // === AUTHENTICATION ===
  { cweId: "CWE-256", name: "Plaintext Storage of Password", description: "Passwords stored without hashing or encryption.", severity: "CRITICAL" as const, category: "Authentication", owaspTop10_2021: "A07:2021", pciDss: "8.2.1", languages: ["all"], remediation: "Use bcrypt/scrypt/Argon2 for password storage.", references: [] },
  { cweId: "CWE-257", name: "Storing Passwords in Recoverable Format", description: "Passwords stored using reversible encryption instead of one-way hashing.", severity: "HIGH" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Use one-way hashing algorithms for passwords.", references: [] },
  { cweId: "CWE-259", name: "Use of Hard-coded Password", description: "Hard-coded passwords in source code.", severity: "CRITICAL" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Use environment variables or secret managers.", references: [] },
  { cweId: "CWE-262", name: "Not Using Password Aging", description: "Software does not enforce password expiration.", severity: "LOW" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Implement password rotation policies.", references: [] },
  { cweId: "CWE-263", name: "Password Aging with Long Expiration", description: "Password expiration set too far in the future.", severity: "LOW" as const, category: "Authentication", languages: ["all"], remediation: "Set reasonable password expiration (90 days).", references: [] },
  { cweId: "CWE-307", name: "Improper Restriction of Excessive Authentication Attempts", description: "No account lockout or rate limiting on login.", severity: "HIGH" as const, category: "Authentication", owaspTop10_2021: "A07:2021", pciDss: "8.1.6", languages: ["all"], remediation: "Implement account lockout, progressive delays, CAPTCHA.", references: [] },
  { cweId: "CWE-308", name: "Use of Single-Factor Authentication", description: "System uses only one authentication factor.", severity: "MEDIUM" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Implement multi-factor authentication (MFA).", references: [] },
  { cweId: "CWE-309", name: "Use of Password System for Primary Authentication", description: "Relying solely on passwords without additional factors.", severity: "MEDIUM" as const, category: "Authentication", languages: ["all"], remediation: "Add MFA options like TOTP, WebAuthn, SMS.", references: [] },
  { cweId: "CWE-521", name: "Weak Password Requirements", description: "Software does not enforce sufficient password complexity.", severity: "MEDIUM" as const, category: "Authentication", owaspTop10_2021: "A07:2021", pciDss: "8.2.3", languages: ["all"], remediation: "Require minimum 8 chars, mixed case, numbers, special characters.", references: [] },
  { cweId: "CWE-620", name: "Unverified Password Change", description: "Password change does not require current password verification.", severity: "HIGH" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Always require current password before allowing changes.", references: [] },
  { cweId: "CWE-640", name: "Weak Password Recovery Mechanism", description: "Password reset mechanism has security weaknesses.", severity: "HIGH" as const, category: "Authentication", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Use secure token-based password reset with expiration.", references: [] },
  // === AUTHORIZATION ===
  { cweId: "CWE-285", name: "Improper Authorization", description: "Software does not correctly perform authorization checks.", severity: "HIGH" as const, category: "Authorization", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Implement centralized authorization; check permissions on every request.", references: [] },
  { cweId: "CWE-269", name: "Improper Privilege Management", description: "Software does not properly manage privileges or permissions.", severity: "HIGH" as const, category: "Authorization", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Follow principle of least privilege; implement RBAC.", references: [] },
  { cweId: "CWE-250", name: "Execution with Unnecessary Privileges", description: "Software runs with higher privileges than necessary.", severity: "HIGH" as const, category: "Authorization", languages: ["all"], remediation: "Run processes with minimum required privileges.", references: [] },
  { cweId: "CWE-266", name: "Incorrect Privilege Assignment", description: "Privilege is assigned incorrectly to a user.", severity: "HIGH" as const, category: "Authorization", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Validate role assignments; implement approval workflows.", references: [] },
  { cweId: "CWE-639", name: "Authorization Bypass Through User-Controlled Key (IDOR)", description: "System uses user-supplied key to access records without authorization check.", severity: "HIGH" as const, category: "Authorization", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Always verify resource ownership; use indirect references.", references: [] },
  { cweId: "CWE-284", name: "Improper Access Control", description: "Software does not restrict access to a resource properly.", severity: "HIGH" as const, category: "Authorization", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Implement access control lists; deny by default.", references: [] },
  // === SESSION MANAGEMENT ===
  { cweId: "CWE-384", name: "Session Fixation", description: "Authenticating user without invalidating existing session ID.", severity: "HIGH" as const, category: "Session Management", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Regenerate session ID after successful authentication.", references: [] },
  { cweId: "CWE-613", name: "Insufficient Session Expiration", description: "Session does not expire or has excessively long timeout.", severity: "MEDIUM" as const, category: "Session Management", owaspTop10_2021: "A07:2021", languages: ["all"], remediation: "Set appropriate session timeouts (15-30 minutes idle).", references: [] },
  { cweId: "CWE-614", name: "Sensitive Cookie Without Secure Flag", description: "Cookie lacks the Secure attribute.", severity: "MEDIUM" as const, category: "Session Management", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Set Secure flag on all sensitive cookies.", references: [] },
  { cweId: "CWE-1004", name: "Sensitive Cookie Without HttpOnly Flag", description: "Cookie accessible via JavaScript.", severity: "MEDIUM" as const, category: "Session Management", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Set HttpOnly flag on session cookies.", references: [] },
  { cweId: "CWE-539", name: "Use of Persistent Cookies Containing Sensitive Information", description: "Sensitive data stored in non-session cookies.", severity: "MEDIUM" as const, category: "Session Management", languages: ["all"], remediation: "Use session-only cookies for sensitive data.", references: [] },
  // === CRYPTOGRAPHY ===
  { cweId: "CWE-261", name: "Weak Encoding for Password", description: "Passwords encoded with weak algorithm like Base64.", severity: "HIGH" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use proper hashing (bcrypt/Argon2), not encoding.", references: [] },
  { cweId: "CWE-310", name: "Cryptographic Issues", description: "General cryptographic weakness in the application.", severity: "MEDIUM" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use vetted crypto libraries; follow NIST recommendations.", references: [] },
  { cweId: "CWE-311", name: "Missing Encryption of Sensitive Data", description: "Sensitive data not encrypted at rest or in transit.", severity: "HIGH" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", pciDss: "3.4", languages: ["all"], remediation: "Encrypt sensitive data using AES-256 at rest, TLS 1.2+ in transit.", references: [] },
  { cweId: "CWE-326", name: "Inadequate Encryption Strength", description: "Cryptographic key too short for intended protection level.", severity: "MEDIUM" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use RSA-2048+, AES-256; follow current NIST key length recommendations.", references: [] },
  { cweId: "CWE-330", name: "Use of Insufficiently Random Values", description: "Software uses predictable random values for security.", severity: "HIGH" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use CSPRNG (crypto.randomBytes, SecureRandom).", references: [] },
  { cweId: "CWE-331", name: "Insufficient Entropy", description: "Not enough randomness in values used for security.", severity: "MEDIUM" as const, category: "Cryptography", languages: ["all"], remediation: "Use system CSPRNG with sufficient output length.", references: [] },
  { cweId: "CWE-338", name: "Use of Cryptographically Weak PRNG", description: "Math.random() or similar weak PRNG used for security purposes.", severity: "HIGH" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["javascript", "python", "java"], remediation: "Use crypto.getRandomValues() or crypto.randomBytes().", references: [] },
  { cweId: "CWE-347", name: "Improper Verification of Cryptographic Signature", description: "Software does not verify digital signatures properly.", severity: "HIGH" as const, category: "Cryptography", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Always verify signatures before trusting signed data.", references: [] },
  // === DATA EXPOSURE ===
  { cweId: "CWE-209", name: "Error Message Information Exposure", description: "Error messages reveal sensitive implementation details.", severity: "MEDIUM" as const, category: "Data Exposure", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Use generic error messages in production; log details server-side.", references: [] },
  { cweId: "CWE-215", name: "Insertion of Sensitive Information Into Debugging Code", description: "Debug code exposes sensitive information in production.", severity: "MEDIUM" as const, category: "Data Exposure", languages: ["all"], remediation: "Remove debug logging in production; use log levels.", references: [] },
  { cweId: "CWE-359", name: "Exposure of Private Personal Information", description: "PII exposed without proper authorization.", severity: "HIGH" as const, category: "Data Exposure", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Implement data classification; apply access controls to PII.", references: [] },
  { cweId: "CWE-532", name: "Insertion of Sensitive Information Into Log File", description: "Sensitive data written to log files.", severity: "MEDIUM" as const, category: "Data Exposure", owaspTop10_2021: "A09:2021", languages: ["all"], remediation: "Mask/redact sensitive data in logs; use structured logging.", references: [] },
  { cweId: "CWE-538", name: "Insertion of Sensitive Information Into Externally-Accessible File", description: "Sensitive data placed in publicly accessible files.", severity: "HIGH" as const, category: "Data Exposure", languages: ["all"], remediation: "Store sensitive files outside web root; set proper permissions.", references: [] },
  { cweId: "CWE-548", name: "Exposure of Information Through Directory Listing", description: "Web server exposes directory contents.", severity: "LOW" as const, category: "Data Exposure", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Disable directory listing in web server configuration.", references: [] },
  // === XSS (additional) ===
  { cweId: "CWE-80", name: "Basic XSS (Script Tags)", description: "Script tags in user input not filtered.", severity: "MEDIUM" as const, category: "XSS", owaspTop10_2021: "A03:2021", languages: ["javascript", "typescript", "php"], remediation: "HTML-encode all user output; use CSP.", references: [] },
  { cweId: "CWE-81", name: "XSS via HTTP Headers", description: "HTTP header values reflected in page without encoding.", severity: "MEDIUM" as const, category: "XSS", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Encode all reflected values regardless of source.", references: [] },
  { cweId: "CWE-83", name: "XSS via Attribute Values", description: "User input in HTML attributes without encoding.", severity: "MEDIUM" as const, category: "XSS", owaspTop10_2021: "A03:2021", languages: ["javascript", "php"], remediation: "Attribute-encode user input in HTML attributes.", references: [] },
  { cweId: "CWE-85", name: "Doubled Character XSS", description: "XSS via double encoding bypass.", severity: "MEDIUM" as const, category: "XSS", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Decode before validation; encode on output.", references: [] },
  { cweId: "CWE-87", name: "XSS via Alternate Syntax", description: "XSS using alternative encoding or syntax.", severity: "MEDIUM" as const, category: "XSS", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Use context-aware output encoding.", references: [] },
  // === FILE HANDLING ===
  { cweId: "CWE-23", name: "Relative Path Traversal", description: "Using '../' in file paths to escape restricted directories.", severity: "HIGH" as const, category: "File Handling", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Canonicalize paths; reject traversal sequences.", references: [] },
  { cweId: "CWE-36", name: "Absolute Path Traversal", description: "Using absolute paths to access restricted files.", severity: "HIGH" as const, category: "File Handling", languages: ["all"], remediation: "Restrict file operations to a specific directory; validate paths.", references: [] },
  { cweId: "CWE-73", name: "External Control of File Name or Path", description: "User controls file name used in file operations.", severity: "HIGH" as const, category: "File Handling", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Use indirect file references; validate against allowlist.", references: [] },
  { cweId: "CWE-377", name: "Insecure Temporary File", description: "Temporary files created insecurely.", severity: "MEDIUM" as const, category: "File Handling", languages: ["all"], remediation: "Use mkstemp() or equivalent; set restrictive permissions.", references: [] },
  { cweId: "CWE-379", name: "Creation of Temp File in Insecure Directory", description: "Temp files in world-writable directories.", severity: "MEDIUM" as const, category: "File Handling", languages: ["all"], remediation: "Use system temp directory with restricted permissions.", references: [] },
  { cweId: "CWE-426", name: "Untrusted Search Path", description: "Software searches untrusted paths for libraries/executables.", severity: "HIGH" as const, category: "File Handling", languages: ["c", "cpp", "python"], remediation: "Use absolute paths; validate PATH environment.", references: [] },
  // === API SECURITY ===
  { cweId: "CWE-235", name: "Improper Handling of Extra Parameters", description: "API processes unexpected or extra parameters.", severity: "MEDIUM" as const, category: "API Security", owaspTop10_2021: "A04:2021", languages: ["all"], remediation: "Implement strict schema validation; reject unknown parameters.", references: [] },
  { cweId: "CWE-400", name: "Uncontrolled Resource Consumption (DoS)", description: "Software does not limit resource usage.", severity: "HIGH" as const, category: "API Security", owaspTop10_2021: "A04:2021", languages: ["all"], remediation: "Implement rate limiting, pagination, timeout, and resource quotas.", references: [] },
  { cweId: "CWE-770", name: "Allocation of Resources Without Limits", description: "No limits on resource allocation per request.", severity: "HIGH" as const, category: "API Security", owaspTop10_2021: "A04:2021", languages: ["all"], remediation: "Set memory/CPU/connection limits; implement circuit breakers.", references: [] },
  { cweId: "CWE-799", name: "Improper Control of Interaction Frequency", description: "No rate limiting on sensitive operations.", severity: "MEDIUM" as const, category: "API Security", owaspTop10_2021: "A04:2021", languages: ["all"], remediation: "Implement rate limiting with token bucket or sliding window.", references: [] },
  { cweId: "CWE-942", name: "Permissive CORS Policy", description: "Overly permissive Cross-Origin Resource Sharing configuration.", severity: "MEDIUM" as const, category: "API Security", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Restrict Access-Control-Allow-Origin to specific trusted domains.", references: [] },
  // === SECURITY MISCONFIGURATION ===
  { cweId: "CWE-16", name: "Configuration", description: "General security misconfiguration weakness.", severity: "MEDIUM" as const, category: "Configuration", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Follow hardening guides; automate configuration management.", references: [] },
  { cweId: "CWE-1021", name: "Improper Restriction of Rendered UI (Clickjacking)", description: "Application can be framed by malicious sites.", severity: "MEDIUM" as const, category: "Configuration", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Set X-Frame-Options: DENY or use CSP frame-ancestors.", references: [] },
  { cweId: "CWE-693", name: "Protection Mechanism Failure", description: "Security mechanism not implemented or bypassable.", severity: "HIGH" as const, category: "Configuration", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Implement defense in depth; test security controls.", references: [] },
  { cweId: "CWE-756", name: "Missing Custom Error Page", description: "Default error pages expose server details.", severity: "LOW" as const, category: "Configuration", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Create custom error pages; hide server information.", references: [] },
  { cweId: "CWE-1188", name: "Insecure Default Initialization", description: "Software defaults are insecure.", severity: "MEDIUM" as const, category: "Configuration", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Use secure defaults; require explicit opt-out of security.", references: [] },
  // === LOGGING & MONITORING ===
  { cweId: "CWE-223", name: "Omission of Security-Relevant Information", description: "Security events not properly logged.", severity: "MEDIUM" as const, category: "Logging", owaspTop10_2021: "A09:2021", languages: ["all"], remediation: "Log authentication, authorization, and data access events.", references: [] },
  { cweId: "CWE-778", name: "Insufficient Logging", description: "Security-relevant actions not logged.", severity: "MEDIUM" as const, category: "Logging", owaspTop10_2021: "A09:2021", languages: ["all"], remediation: "Implement comprehensive audit logging; use SIEM.", references: [] },
  { cweId: "CWE-779", name: "Logging of Excessive Data", description: "Too much data in logs including sensitive information.", severity: "MEDIUM" as const, category: "Logging", owaspTop10_2021: "A09:2021", languages: ["all"], remediation: "Log only necessary data; redact PII and secrets.", references: [] },
  // === SUPPLY CHAIN ===
  { cweId: "CWE-506", name: "Embedded Malicious Code", description: "Intentionally malicious code within software.", severity: "CRITICAL" as const, category: "Supply Chain", owaspTop10_2021: "A08:2021", languages: ["all"], remediation: "Code review; use SCA tools; verify package integrity.", references: [] },
  { cweId: "CWE-507", name: "Trojan Horse", description: "Software contains hidden malicious functionality.", severity: "CRITICAL" as const, category: "Supply Chain", owaspTop10_2021: "A08:2021", languages: ["all"], remediation: "Use signed packages; verify checksums; audit dependencies.", references: [] },
  { cweId: "CWE-494", name: "Download of Code Without Integrity Check", description: "Software downloads executable code without verifying integrity.", severity: "HIGH" as const, category: "Supply Chain", owaspTop10_2021: "A08:2021", languages: ["all"], remediation: "Verify checksums and signatures of downloaded code.", references: [] },
  { cweId: "CWE-937", name: "Using Components with Known Vulnerabilities", description: "Application uses a library version with known CVEs.", severity: "HIGH" as const, category: "Supply Chain", owaspTop10_2021: "A06:2021", languages: ["all"], remediation: "Regularly scan and update dependencies; use Dependabot/Snyk.", references: [] },
  // === MEMORY SAFETY (additional) ===
  { cweId: "CWE-119", name: "Buffer Overflow", description: "Operations on a buffer without proper bounds checking.", severity: "CRITICAL" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Use safe string functions; enable stack canaries; use ASLR.", references: [] },
  { cweId: "CWE-120", name: "Classic Buffer Overflow", description: "Copying input to a fixed-size buffer without bounds check.", severity: "CRITICAL" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Use strncpy/snprintf instead of strcpy/sprintf.", references: [] },
  { cweId: "CWE-121", name: "Stack-based Buffer Overflow", description: "Buffer overflow on the stack.", severity: "CRITICAL" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Enable stack protection; use safe functions.", references: [] },
  { cweId: "CWE-122", name: "Heap-based Buffer Overflow", description: "Buffer overflow in heap-allocated memory.", severity: "CRITICAL" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Use safe allocation patterns; validate sizes.", references: [] },
  { cweId: "CWE-131", name: "Incorrect Calculation of Buffer Size", description: "Buffer allocated with incorrect size.", severity: "HIGH" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Verify size calculations; account for null terminators.", references: [] },
  { cweId: "CWE-190", name: "Integer Overflow or Wraparound", description: "Integer operations exceed the maximum value.", severity: "HIGH" as const, category: "Memory Safety", languages: ["c", "cpp", "java"], remediation: "Check for overflow before operations; use safe math libraries.", references: [] },
  { cweId: "CWE-191", name: "Integer Underflow", description: "Integer subtraction produces value below minimum.", severity: "HIGH" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Validate operands before subtraction.", references: [] },
  { cweId: "CWE-415", name: "Double Free", description: "Memory freed twice causing heap corruption.", severity: "CRITICAL" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Set pointers to NULL after free; use smart pointers.", references: [] },
  { cweId: "CWE-476", name: "NULL Pointer Dereference", description: "Dereferencing a null pointer causing crash.", severity: "MEDIUM" as const, category: "Memory Safety", languages: ["c", "cpp", "java", "csharp"], remediation: "Check for null before dereferencing; use Optional types.", references: [] },
  { cweId: "CWE-763", name: "Release of Invalid Pointer or Reference", description: "Freeing memory that was not allocated.", severity: "HIGH" as const, category: "Memory Safety", languages: ["c", "cpp"], remediation: "Track allocations; use RAII patterns.", references: [] },
  // === CONCURRENCY ===
  { cweId: "CWE-362", name: "Race Condition (TOCTOU)", description: "Time-of-check to time-of-use race condition.", severity: "HIGH" as const, category: "Concurrency", languages: ["all"], remediation: "Use atomic operations, file locks, or database transactions.", references: [] },
  { cweId: "CWE-366", name: "Race Condition Within Thread", description: "Shared resource accessed without synchronization.", severity: "MEDIUM" as const, category: "Concurrency", languages: ["java", "csharp", "cpp", "go"], remediation: "Use mutexes, synchronized blocks, or atomic variables.", references: [] },
  { cweId: "CWE-367", name: "TOCTOU Race Condition", description: "Check and use of resource not atomic.", severity: "HIGH" as const, category: "Concurrency", languages: ["all"], remediation: "Perform check and operation atomically.", references: [] },
  { cweId: "CWE-543", name: "Use of Singleton Without Synchronization", description: "Singleton accessed from multiple threads without locking.", severity: "MEDIUM" as const, category: "Concurrency", languages: ["java", "csharp", "cpp"], remediation: "Use thread-safe singleton patterns (double-checked locking).", references: [] },
  // === ERROR HANDLING ===
  { cweId: "CWE-252", name: "Unchecked Return Value", description: "Return value of function not checked.", severity: "LOW" as const, category: "Error Handling", languages: ["c", "cpp", "java"], remediation: "Always check return values of security-critical functions.", references: [] },
  { cweId: "CWE-390", name: "Detection of Error Without Action", description: "Error detected but not properly handled.", severity: "MEDIUM" as const, category: "Error Handling", languages: ["all"], remediation: "Implement proper error handling and recovery.", references: [] },
  { cweId: "CWE-391", name: "Unchecked Error Condition", description: "Error conditions not checked or handled.", severity: "MEDIUM" as const, category: "Error Handling", languages: ["all"], remediation: "Use try-catch; check all error returns.", references: [] },
  { cweId: "CWE-396", name: "Catching Generic Exception", description: "Code catches overly broad exception types.", severity: "LOW" as const, category: "Error Handling", languages: ["java", "python", "csharp"], remediation: "Catch specific exceptions; handle each appropriately.", references: [] },
  { cweId: "CWE-397", name: "Throwing Generic Exception", description: "Code throws overly broad exception types.", severity: "LOW" as const, category: "Error Handling", languages: ["java", "python", "csharp"], remediation: "Throw specific exception types.", references: [] },
  { cweId: "CWE-754", name: "Improper Check for Unusual Conditions", description: "Software does not check for unusual error conditions.", severity: "MEDIUM" as const, category: "Error Handling", languages: ["all"], remediation: "Handle all edge cases including timeouts, partial data, etc.", references: [] },
  { cweId: "CWE-755", name: "Improper Handling of Exceptional Conditions", description: "Software does not handle exceptions correctly.", severity: "MEDIUM" as const, category: "Error Handling", languages: ["all"], remediation: "Implement comprehensive exception handling strategy.", references: [] },
  // === CLOUD & CONTAINER SECURITY ===
  { cweId: "CWE-250", name: "Execution with Unnecessary Privileges (Cloud)", description: "Cloud workload running with excessive IAM permissions.", severity: "HIGH" as const, category: "Cloud Security", languages: ["all"], remediation: "Apply least privilege IAM policies; use service accounts.", references: [] },
  { cweId: "CWE-732", name: "Incorrect Permission Assignment (S3/Storage)", description: "Cloud storage has overly permissive access policies.", severity: "HIGH" as const, category: "Cloud Security", languages: ["all"], remediation: "Set strict bucket policies; disable public access by default.", references: [] },
  { cweId: "CWE-1275", name: "Sensitive Cookie with Improper SameSite Attribute", description: "Cookie missing or has incorrect SameSite configuration.", severity: "MEDIUM" as const, category: "Cloud Security", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Set SameSite=Strict or SameSite=Lax.", references: [] },
  // === MOBILE SECURITY ===
  { cweId: "CWE-312", name: "Cleartext Storage on Mobile Device", description: "Sensitive data stored unencrypted on mobile device.", severity: "HIGH" as const, category: "Mobile Security", languages: ["swift", "kotlin", "java"], remediation: "Use iOS Keychain or Android Keystore for sensitive data.", references: [] },
  { cweId: "CWE-919", name: "Weaknesses in Mobile Applications", description: "General mobile security weakness.", severity: "MEDIUM" as const, category: "Mobile Security", languages: ["swift", "kotlin", "java"], remediation: "Follow OWASP Mobile Top 10; use platform security features.", references: [] },
  { cweId: "CWE-921", name: "Storage of Sensitive Data in Publicly Accessible Location", description: "Mobile app stores sensitive data in shared storage.", severity: "HIGH" as const, category: "Mobile Security", languages: ["kotlin", "java", "swift"], remediation: "Use private app storage; encrypt sensitive files.", references: [] },
  // === BUSINESS LOGIC ===
  { cweId: "CWE-840", name: "Business Logic Errors", description: "Flaws in business logic allowing unintended behavior.", severity: "HIGH" as const, category: "Business Logic", languages: ["all"], remediation: "Implement thorough business rule validation and testing.", references: [] },
  { cweId: "CWE-841", name: "Improper Enforcement of Behavioral Workflow", description: "Software does not enforce expected operation sequence.", severity: "MEDIUM" as const, category: "Business Logic", languages: ["all"], remediation: "Implement state machines; validate workflow transitions.", references: [] },
  { cweId: "CWE-837", name: "Improper Enforcement of Single, Unique Action", description: "Same action can be performed multiple times when only once is intended.", severity: "MEDIUM" as const, category: "Business Logic", languages: ["all"], remediation: "Use idempotency keys; implement transaction locks.", references: [] },
  // === NETWORK ===
  { cweId: "CWE-295", name: "Improper Certificate Validation", description: "Software does not validate SSL/TLS certificates properly.", severity: "HIGH" as const, category: "Network", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use default certificate validation; pin certificates for critical connections.", references: [] },
  { cweId: "CWE-297", name: "Improper Validation of Certificate with Host Mismatch", description: "Certificate hostname not checked against connection target.", severity: "HIGH" as const, category: "Network", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Enable hostname verification in TLS connections.", references: [] },
  { cweId: "CWE-300", name: "Channel Accessible by Non-Endpoint", description: "Communication channel accessible to man-in-the-middle.", severity: "HIGH" as const, category: "Network", languages: ["all"], remediation: "Use end-to-end encryption; implement mutual TLS.", references: [] },
  // === COMPLIANCE SPECIFIC ===
  { cweId: "CWE-257", name: "Storing Passwords in Recoverable Format (PCI)", description: "PCI DSS 8.2.1: Passwords must not be recoverable.", severity: "HIGH" as const, category: "Compliance", pciDss: "8.2.1", languages: ["all"], remediation: "Use one-way hashing with bcrypt/Argon2.", references: [] },
  { cweId: "CWE-523", name: "Unprotected Transport of Credentials", description: "Credentials sent without encryption.", severity: "HIGH" as const, category: "Compliance", owaspTop10_2021: "A02:2021", pciDss: "4.1", languages: ["all"], remediation: "Always use HTTPS/TLS for credential transmission.", references: [] },
  { cweId: "CWE-522", name: "Insufficiently Protected Credentials", description: "Credentials not adequately protected.", severity: "HIGH" as const, category: "Compliance", owaspTop10_2021: "A07:2021", pciDss: "8.2", languages: ["all"], remediation: "Hash passwords; encrypt tokens; use secure storage.", references: [] },
  // === ADDITIONAL HIGH-IMPACT ===
  { cweId: "CWE-74", name: "Injection", description: "General injection weakness — user input embedded in generated output.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Always separate data from code; use parameterized interfaces.", references: [] },
  { cweId: "CWE-116", name: "Improper Encoding or Escaping of Output", description: "Output not properly encoded for the output context.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["all"], remediation: "Use context-aware output encoding for HTML, JS, URL, etc.", references: [] },
  { cweId: "CWE-134", name: "Use of Externally-Controlled Format String", description: "User input used as format string argument.", severity: "CRITICAL" as const, category: "Injection", languages: ["c", "cpp"], remediation: "Never pass user input as format string; use fixed format strings.", references: [] },
  { cweId: "CWE-178", name: "Improper Handling of Case Sensitivity", description: "Security check bypassed via case manipulation.", severity: "MEDIUM" as const, category: "Input Validation", languages: ["all"], remediation: "Normalize input case before security comparisons.", references: [] },
  { cweId: "CWE-185", name: "Incorrect Regular Expression", description: "Flawed regex allowing bypass.", severity: "MEDIUM" as const, category: "Input Validation", languages: ["all"], remediation: "Test regexes thoroughly; use anchors; beware ReDoS.", references: [] },
  { cweId: "CWE-1333", name: "Inefficient Regular Expression Complexity (ReDoS)", description: "Regex with catastrophic backtracking causing denial of service.", severity: "HIGH" as const, category: "Input Validation", owaspTop10_2021: "A04:2021", languages: ["javascript", "python", "java"], remediation: "Avoid nested quantifiers; use RE2 or timeout on regex execution.", references: [] },
  { cweId: "CWE-345", name: "Insufficient Verification of Data Authenticity", description: "Data accepted without verifying its authenticity.", severity: "HIGH" as const, category: "Input Validation", owaspTop10_2021: "A08:2021", languages: ["all"], remediation: "Verify signatures, MACs, or checksums on received data.", references: [] },
  { cweId: "CWE-346", name: "Origin Validation Error", description: "Software does not verify the origin of data.", severity: "MEDIUM" as const, category: "Input Validation", owaspTop10_2021: "A05:2021", languages: ["all"], remediation: "Validate Origin/Referer headers; implement CORS properly.", references: [] },
  { cweId: "CWE-436", name: "Interpretation Conflict", description: "Different components interpret data differently.", severity: "MEDIUM" as const, category: "Input Validation", languages: ["all"], remediation: "Normalize data before processing; use canonical forms.", references: [] },
  { cweId: "CWE-610", name: "Externally Controlled Reference to Resource", description: "Software references external resource controlled by attacker.", severity: "HIGH" as const, category: "Input Validation", owaspTop10_2021: "A10:2021", languages: ["all"], remediation: "Validate and restrict external resource references.", references: [] },
  { cweId: "CWE-776", name: "XML Entity Expansion (Billion Laughs)", description: "XML bomb causing denial of service.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A05:2021", languages: ["java", "python", "csharp"], remediation: "Disable DTD processing; set entity expansion limits.", references: [] },
  { cweId: "CWE-943", name: "Improper Neutralization in NoSQL Query", description: "NoSQL injection via unfiltered user input.", severity: "HIGH" as const, category: "Injection", owaspTop10_2021: "A03:2021", languages: ["javascript", "python"], remediation: "Use parameterized queries; validate input types.", references: [] },
  { cweId: "CWE-1236", name: "CSV Injection (Formula Injection)", description: "User input in CSV can execute formulas in spreadsheets.", severity: "MEDIUM" as const, category: "Injection", languages: ["all"], remediation: "Prefix values with single quote; strip = + - @ characters.", references: [] },
  { cweId: "CWE-1270", name: "Generation of Incorrect Security Tokens", description: "Security tokens generated with insufficient randomness.", severity: "HIGH" as const, category: "Authentication", owaspTop10_2021: "A02:2021", languages: ["all"], remediation: "Use CSPRNG for token generation; ensure sufficient entropy.", references: [] },
  // === PRIVACY ===
  { cweId: "CWE-359", name: "Exposure of Private Information (Privacy Violation)", description: "Software exposes personal data inappropriately.", severity: "HIGH" as const, category: "Privacy", owaspTop10_2021: "A01:2021", languages: ["all"], remediation: "Implement data minimization; apply GDPR/CCPA controls.", references: [] },
  // === INFRASTRUCTURE ===
  { cweId: "CWE-668", name: "Exposure of Resource to Wrong Sphere", description: "Resource accessible to unauthorized parties.", severity: "HIGH" as const, category: "Infrastructure", languages: ["all"], remediation: "Implement proper access controls; segment networks.", references: [] },
  { cweId: "CWE-669", name: "Incorrect Resource Transfer Between Spheres", description: "Data flows between trust boundaries without validation.", severity: "HIGH" as const, category: "Infrastructure", languages: ["all"], remediation: "Validate data at trust boundaries; implement API gateways.", references: [] },
];

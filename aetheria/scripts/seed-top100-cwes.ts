/**
 * MITRE Top 100 CWEs Seed (2019-2024)
 * Pre-fills ComplianceMapping + additional TaintSinks for the most dangerous CWEs.
 * Data sourced from: MITRE CWE Top 25 (2019-2024), NIST NVD, PCI-DSS v4.0, HIPAA, ISO 27001:2022
 * Run: npx tsx scripts/seed-top100-cwes.ts
 */
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

// MITRE Top 100 Most Dangerous CWEs (compiled 2019-2024 rankings)
// Format: [CWE-ID, Name, OWASP2021, OWASP2017, PCI-DSS, HIPAA, NIST800-53, ISO27001, MITRE-rank]
const TOP100: [string, string, string | null, string | null, string | null, string | null, string | null, string | null, number][] = [
  ["CWE-787", "Out-of-bounds Write", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 1],
  ["CWE-79", "Cross-site Scripting", "A03:2021", "A7", "6.5.7", "164.312(a)(1)", "SI-10", "A.14.2.5", 2],
  ["CWE-89", "SQL Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 3],
  ["CWE-416", "Use After Free", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 4],
  ["CWE-78", "OS Command Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 5],
  ["CWE-20", "Improper Input Validation", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 6],
  ["CWE-125", "Out-of-bounds Read", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 7],
  ["CWE-22", "Path Traversal", "A01:2021", "A5", "6.5.8", "164.312(a)(1)", "AC-3", "A.14.2.5", 8],
  ["CWE-352", "Cross-Site Request Forgery", "A01:2021", "A8", "6.5.8", "164.312(a)(1)", "SC-23", "A.14.2.5", 9],
  ["CWE-434", "Unrestricted File Upload", "A04:2021", "A1", "6.5.8", "164.312(a)(1)", "SI-3", "A.14.2.5", 10],
  ["CWE-862", "Missing Authorization", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-3", "A.9.4.1", 11],
  ["CWE-476", "NULL Pointer Dereference", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 12],
  ["CWE-287", "Improper Authentication", "A07:2021", "A2", "8.2", "164.312(d)", "IA-2", "A.9.4.2", 13],
  ["CWE-190", "Integer Overflow", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 14],
  ["CWE-502", "Insecure Deserialization", "A08:2021", "A8", "6.5.8", "164.312(a)(1)", "SI-10", "A.14.2.5", 15],
  ["CWE-77", "Command Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 16],
  ["CWE-119", "Buffer Overflow", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 17],
  ["CWE-798", "Hardcoded Credentials", "A07:2021", "A2", "8.2.1", "164.312(a)(2)(i)", "IA-5", "A.9.4.3", 18],
  ["CWE-918", "Server-Side Request Forgery", "A10:2021", "A10", "6.5.8", "164.312(a)(1)", "SC-7", "A.14.2.5", 19],
  ["CWE-306", "Missing Authentication", "A07:2021", "A2", "8.2", "164.312(d)", "IA-2", "A.9.4.1", 20],
  ["CWE-400", "Resource Exhaustion (DoS)", "A05:2021", "A6", "6.5.8", null, "SC-5", "A.12.1.3", 21],
  ["CWE-269", "Improper Privilege Management", "A01:2021", "A5", "7.1.2", "164.312(a)(1)", "AC-6", "A.9.2.3", 22],
  ["CWE-284", "Improper Access Control", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-3", "A.14.1.3", 23],
  ["CWE-200", "Information Exposure", "A01:2021", "A3", "6.5.5", "164.312(a)(1)", "SI-11", "A.14.1.3", 24],
  ["CWE-732", "Incorrect Permission Assignment", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-6", "A.9.4.1", 25],
  ["CWE-362", "Race Condition", "A04:2021", null, "6.5.8", null, "SI-16", "A.14.2.5", 26],
  ["CWE-209", "Error Message Information Leak", "A01:2021", "A3", "6.5.5", "164.312(a)(1)", "SI-11", "A.14.1.3", 27],
  ["CWE-120", "Classic Buffer Overflow", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 28],
  ["CWE-203", "Observable Discrepancy", null, null, null, null, "SI-16", null, 29],
  ["CWE-74", "Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 30],
  ["CWE-94", "Code Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 31],
  ["CWE-863", "Incorrect Authorization", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-3", "A.9.4.1", 32],
  ["CWE-276", "Incorrect Default Permissions", "A05:2021", "A5", "7.1", "164.312(a)(1)", "AC-6", "A.9.4.1", 33],
  ["CWE-93", "CRLF Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 34],
  ["CWE-401", "Memory Leak", null, null, null, null, "SI-16", null, 35],
  ["CWE-428", "Unquoted Search Path", null, null, null, null, "CM-7", null, 36],
  ["CWE-427", "Uncontrolled Search Path", "A08:2021", null, "6.5.8", null, "CM-7", "A.14.2.7", 37],
  ["CWE-611", "XML External Entities (XXE)", "A05:2021", "A4", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 38],
  ["CWE-601", "Open Redirect", "A01:2021", "A6", "6.5.8", "164.312(a)(1)", "SI-10", "A.14.2.5", 39],
  ["CWE-134", "Format String", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 40],
  ["CWE-295", "Improper Certificate Validation", "A02:2021", "A3", "4.1", "164.312(e)(1)", "SC-23", "A.13.2.1", 41],
  ["CWE-835", "Infinite Loop", "A05:2021", null, "6.5.8", null, "SC-5", "A.12.1.3", 42],
  ["CWE-913", "Mass Assignment", "A04:2021", null, "6.5.8", "164.312(a)(1)", "AC-3", "A.14.2.5", 43],
  ["CWE-311", "Missing Encryption", "A02:2021", "A3", "3.4", "164.312(e)(2)(ii)", "SC-8", "A.10.1.1", 44],
  ["CWE-754", "Improper Exceptional Conditions", null, null, null, null, "SI-16", null, 45],
  ["CWE-59", "Link Following (Symlink)", "A01:2021", null, "6.5.8", null, "AC-3", "A.14.2.5", 46],
  ["CWE-384", "Session Fixation", "A07:2021", "A2", "6.5.8", "164.312(a)(1)", "SC-23", "A.9.4.2", 47],
  ["CWE-770", "Allocation Without Limits", "A05:2021", "A6", "6.5.8", null, "SC-5", "A.12.1.3", 48],
  ["CWE-426", "Untrusted Search Path", "A08:2021", null, "6.5.8", null, "CM-7", "A.14.2.7", 49],
  ["CWE-250", "Unnecessary Privileges", "A05:2021", "A5", "7.1.2", "164.312(a)(1)", "AC-6", "A.9.2.3", 50],
  ["CWE-327", "Broken Crypto", "A02:2021", "A3", "3.4", "164.312(e)(2)(ii)", "SC-13", "A.10.1.1", 51],
  ["CWE-668", "Exposure to Wrong Sphere", "A05:2021", "A5", "6.5.8", "164.312(a)(1)", "AC-3", "A.14.1.3", 52],
  ["CWE-916", "Insufficient Computational Effort (Hash)", "A02:2021", null, "3.4", "164.312(e)(2)(ii)", "SC-13", "A.10.1.1", 53],
  ["CWE-667", "Improper Locking", null, null, null, null, "SI-16", null, 54],
  ["CWE-755", "Improper Handling of Exceptional Conditions", null, null, null, null, "SI-16", null, 55],
  ["CWE-1021", "Clickjacking", "A05:2021", null, "6.5.8", null, "SC-23", "A.14.1.3", 56],
  ["CWE-369", "Divide By Zero", null, null, null, null, "SI-16", null, 57],
  ["CWE-285", "Improper Authorization", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-3", "A.9.4.1", 58],
  ["CWE-772", "Missing Resource Release", null, null, null, null, "SC-5", null, 59],
  ["CWE-404", "Improper Resource Shutdown", null, null, null, null, "SC-5", null, 60],
  ["CWE-681", "Incorrect Conversion between Numeric Types", null, null, null, null, "SI-16", null, 61],
  ["CWE-290", "Authentication Bypass by Spoofing", "A07:2021", "A2", "8.2", "164.312(d)", "IA-2", "A.9.4.2", 62],
  ["CWE-252", "Unchecked Return Value", null, null, null, null, "SI-16", null, 63],
  ["CWE-674", "Uncontrolled Recursion", "A05:2021", null, "6.5.8", null, "SC-5", "A.12.1.3", 64],
  ["CWE-319", "Cleartext Transmission", "A02:2021", "A3", "4.1", "164.312(e)(1)", "SC-8", "A.13.2.1", 65],
  ["CWE-922", "Insecure Storage", "A04:2021", null, "3.4", "164.312(e)(2)(ii)", "SC-28", "A.10.1.1", 66],
  ["CWE-201", "Sensitive Data in Response", "A01:2021", "A3", "6.5.5", "164.312(a)(1)", "SI-11", "A.14.1.3", 67],
  ["CWE-924", "Message Integrity Check Missing", "A08:2021", null, "6.5.8", null, "SI-7", "A.14.2.5", 68],
  ["CWE-639", "IDOR (Insecure Direct Object Reference)", "A01:2021", "A5", "7.1", "164.312(a)(1)", "AC-3", "A.9.4.1", 69],
  ["CWE-346", "Origin Validation Error", "A05:2021", null, "6.5.8", null, "SC-23", "A.14.1.3", 70],
  ["CWE-706", "Use of Incorrectly-Resolved Name", null, null, null, null, "SI-16", null, 71],
  ["CWE-122", "Heap-based Buffer Overflow", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 72],
  ["CWE-191", "Integer Underflow", null, null, null, null, "SI-16", null, 73],
  ["CWE-1336", "Server-Side Template Injection", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 74],
  ["CWE-843", "Type Confusion", null, null, null, null, "SI-16", null, 75],
  ["CWE-330", "Insufficient Randomness", "A02:2021", "A3", "3.4", "164.312(e)(2)(ii)", "SC-13", "A.10.1.1", 76],
  ["CWE-347", "Improper Signature Verification", "A02:2021", null, "4.1", null, "SI-7", "A.14.2.5", 77],
  ["CWE-338", "Weak PRNG", "A02:2021", "A3", "3.4", "164.312(e)(2)(ii)", "SC-13", "A.10.1.1", 78],
  ["CWE-908", "Uninitialized Resource", null, null, null, null, "SI-16", null, 79],
  ["CWE-345", "Insufficient Data Authenticity", "A08:2021", null, "6.5.8", null, "SI-7", "A.14.2.5", 80],
  ["CWE-789", "Uncontrolled Memory Allocation", null, null, null, null, "SC-5", null, 81],
  ["CWE-331", "Insufficient Entropy", "A02:2021", null, "3.4", "164.312(e)(2)(ii)", "SC-13", "A.10.1.1", 82],
  ["CWE-522", "Insufficiently Protected Credentials", "A07:2021", "A2", "8.2.1", "164.312(a)(2)(i)", "IA-5", "A.9.4.3", 83],
  ["CWE-824", "Access of Uninitialized Pointer", null, null, null, null, "SI-16", null, 84],
  ["CWE-778", "Insufficient Logging", "A09:2021", "A10", "10.2", "164.312(b)", "AU-2", "A.12.4.1", 85],
  ["CWE-532", "Information in Log File", "A09:2021", "A3", "10.2", "164.312(b)", "AU-9", "A.12.4.1", 86],
  ["CWE-294", "Authentication Bypass by Capture-replay", "A07:2021", null, "8.2", "164.312(d)", "IA-2", "A.9.4.2", 87],
  ["CWE-321", "Hardcoded Crypto Key", "A02:2021", "A3", "3.5.2", "164.312(e)(2)(ii)", "SC-12", "A.10.1.2", 88],
  ["CWE-697", "Incorrect Comparison", null, null, null, null, "SI-16", null, 89],
  ["CWE-665", "Improper Initialization", null, null, null, null, "SI-16", null, 90],
  ["CWE-312", "Cleartext Storage", "A04:2021", "A3", "3.4", "164.312(e)(2)(ii)", "SC-28", "A.10.1.1", 91],
  ["CWE-1104", "Unmaintained Third-Party Components", "A06:2021", "A9", "6.3.2", null, "CM-2", "A.14.2.2", 92],
  ["CWE-494", "Download Without Integrity Check", "A08:2021", "A8", "6.3.2", null, "CM-7", "A.14.2.7", 93],
  ["CWE-829", "Inclusion from Untrusted Source", "A08:2021", null, "6.5.8", null, "CM-7", "A.14.2.7", 94],
  ["CWE-98", "Remote File Inclusion", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 95],
  ["CWE-672", "Expired Resource Usage", null, null, null, null, "SC-5", null, 96],
  ["CWE-676", "Use of Potentially Dangerous Function", null, null, "6.5.1", null, "SI-16", "A.14.2.5", 97],
  ["CWE-113", "HTTP Response Splitting", "A03:2021", null, "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 98],
  ["CWE-116", "Improper Encoding/Escaping", "A03:2021", "A1", "6.5.1", "164.312(a)(1)", "SI-10", "A.14.2.5", 99],
  ["CWE-407", "Algorithmic Complexity", "A05:2021", null, "6.5.8", null, "SC-5", "A.12.1.3", 100],
];

// Additional taint sinks for CWEs not yet covered (detectable via source→sink)
const ADDITIONAL_SINKS: { language: string; pattern: string; cwe: string; category: string; severity: string; owasp2021: string }[] = [
  // CSRF (CWE-352)
  { language: "javascript", pattern: "app\\.(?:post|put|delete|patch)\\s*\\((?!.*csrf)", cwe: "CWE-352", category: "Cross-Site Request Forgery", severity: "HIGH", owasp2021: "A01:2021" },
  // File Upload (CWE-434)
  { language: "javascript", pattern: "multer\\s*\\(|upload\\.(single|array|any)\\s*\\(", cwe: "CWE-434", category: "Unrestricted File Upload", severity: "HIGH", owasp2021: "A04:2021" },
  { language: "php", pattern: "move_uploaded_file\\s*\\(", cwe: "CWE-434", category: "Unrestricted File Upload", severity: "HIGH", owasp2021: "A04:2021" },
  { language: "python", pattern: "file\\.save\\s*\\(|save_uploaded_file", cwe: "CWE-434", category: "Unrestricted File Upload", severity: "HIGH", owasp2021: "A04:2021" },
  // XXE (CWE-611)
  { language: "javascript", pattern: "libxmljs|xml2js|DOMParser|parseXml", cwe: "CWE-611", category: "XML External Entities", severity: "HIGH", owasp2021: "A05:2021" },
  { language: "java", pattern: "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory", cwe: "CWE-611", category: "XML External Entities", severity: "HIGH", owasp2021: "A05:2021" },
  { language: "python", pattern: "xml\\.etree|lxml\\.etree|xml\\.dom|xml\\.sax", cwe: "CWE-611", category: "XML External Entities", severity: "HIGH", owasp2021: "A05:2021" },
  // Open Redirect (CWE-601) - more patterns
  { language: "python", pattern: "redirect\\s*\\(.*request", cwe: "CWE-601", category: "Open Redirect", severity: "MEDIUM", owasp2021: "A01:2021" },
  // IDOR (CWE-639)
  { language: "javascript", pattern: "findById\\s*\\(\\s*req\\.(params|query|body)", cwe: "CWE-639", category: "Insecure Direct Object Reference", severity: "HIGH", owasp2021: "A01:2021" },
  // Session Fixation (CWE-384)
  { language: "javascript", pattern: "session\\.regenerate|req\\.session\\.id", cwe: "CWE-384", category: "Session Fixation", severity: "MEDIUM", owasp2021: "A07:2021" },
  // Cleartext Storage (CWE-312)
  { language: "javascript", pattern: "localStorage\\.setItem\\s*\\(.*(password|token|secret|key)", cwe: "CWE-312", category: "Cleartext Storage", severity: "HIGH", owasp2021: "A04:2021" },
  { language: "python", pattern: "open\\s*\\(.*['\"]w['\"].*password|write\\s*\\(.*password", cwe: "CWE-312", category: "Cleartext Storage", severity: "HIGH", owasp2021: "A04:2021" },
  // Information in Logs (CWE-532)
  { language: "javascript", pattern: "console\\.(log|info|warn)\\s*\\(.*(password|token|secret|key|credential)", cwe: "CWE-532", category: "Information in Log", severity: "MEDIUM", owasp2021: "A09:2021" },
  { language: "python", pattern: "logging\\.(info|debug|warning)\\s*\\(.*(password|token|secret|key)", cwe: "CWE-532", category: "Information in Log", severity: "MEDIUM", owasp2021: "A09:2021" },
  // Weak Hash (CWE-916)
  { language: "javascript", pattern: "createHash\\s*\\(\\s*['\"]md5['\"]\\).*password|createHash\\s*\\(\\s*['\"]sha1['\"]\\).*password", cwe: "CWE-916", category: "Insufficient Hash", severity: "HIGH", owasp2021: "A02:2021" },
  // Missing Auth (CWE-306)
  { language: "javascript", pattern: "router\\.(get|post|put|delete)\\s*\\([^,]+,\\s*(?!.*auth)(?!.*middleware)", cwe: "CWE-306", category: "Missing Authentication", severity: "MEDIUM", owasp2021: "A07:2021" },
  // CRLF Injection (CWE-93)
  { language: "javascript", pattern: "setHeader\\s*\\(.*req\\.|res\\.writeHead\\s*\\(.*req\\.", cwe: "CWE-93", category: "CRLF Injection", severity: "MEDIUM", owasp2021: "A03:2021" },
  { language: "python", pattern: "response\\.headers\\s*\\[.*request", cwe: "CWE-93", category: "CRLF Injection", severity: "MEDIUM", owasp2021: "A03:2021" },
  // Mass Assignment (CWE-913)
  { language: "javascript", pattern: "Object\\.assign\\s*\\(.*req\\.body|\\{\\s*\\.\\.\\.req\\.body", cwe: "CWE-913", category: "Mass Assignment", severity: "MEDIUM", owasp2021: "A04:2021" },
  { language: "ruby", pattern: "new\\s*\\(\\s*params|update\\s*\\(\\s*params", cwe: "CWE-913", category: "Mass Assignment", severity: "HIGH", owasp2021: "A04:2021" },
  // Python command injection extras
  { language: "python", pattern: "os\\.exec(l|v|le|ve|lp|vp|lpe|vpe)?\\s*\\(", cwe: "CWE-78", category: "OS Command Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  // Java XXE
  { language: "java", pattern: "TransformerFactory|SchemaFactory|XPathFactory", cwe: "CWE-611", category: "XML External Entities", severity: "HIGH", owasp2021: "A05:2021" },
  // PHP LFI/RFI extras
  { language: "php", pattern: "readfile\\s*\\(.*\\$|file\\s*\\(.*\\$", cwe: "CWE-22", category: "Path Traversal", severity: "HIGH", owasp2021: "A01:2021" },
  // Go template injection
  { language: "go", pattern: "template\\.New\\s*\\(.*r\\.", cwe: "CWE-1336", category: "Server-Side Template Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  // Generic: NoSQL injection
  { language: "javascript", pattern: "\\$where.*req\\.|\\$regex.*req\\.", cwe: "CWE-943", category: "NoSQL Injection", severity: "CRITICAL", owasp2021: "A03:2021" },
  { language: "javascript", pattern: "find\\s*\\(\\s*req\\.(body|query|params)", cwe: "CWE-943", category: "NoSQL Injection", severity: "HIGH", owasp2021: "A03:2021" },
];

async function main() {
  console.log("[SEED-TOP100] Seeding MITRE Top 100 CWEs (2019-2024)...");

  // 1. Compliance Mappings (upsert all 100)
  console.log(`[SEED-TOP100] Upserting ${TOP100.length} compliance mappings...`);
  for (const [cwe, name, owasp2021, owasp2017, pciDss, hipaa, nist, iso, rank] of TOP100) {
    await prisma.complianceMapping.upsert({
      where: { cwe },
      update: { pciDss, hipaa, nist80053: nist, iso27001: iso, owasp2021, owasp2017, mitreTop25: rank },
      create: { cwe, pciDss, hipaa, nist80053: nist, iso27001: iso, owasp2021, owasp2017, mitreTop25: rank },
    });
  }

  // 2. Additional Taint Sinks
  console.log(`[SEED-TOP100] Adding ${ADDITIONAL_SINKS.length} additional taint sinks...`);
  let addedSinks = 0;
  for (const sink of ADDITIONAL_SINKS) {
    const existing = await prisma.taintSink.findFirst({ where: { language: sink.language, pattern: sink.pattern } });
    if (!existing) {
      await prisma.taintSink.create({ data: { language: sink.language, pattern: sink.pattern, cwe: sink.cwe, category: sink.category, severity: sink.severity, owasp2021: sink.owasp2021 } });
      addedSinks++;
    }
  }

  // 3. Add CWE-943 (NoSQL Injection) to compliance
  await prisma.complianceMapping.upsert({
    where: { cwe: "CWE-943" },
    update: { pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1", mitreTop25: null },
    create: { cwe: "CWE-943", pciDss: "6.5.1", hipaa: "164.312(a)(1)", nist80053: "SI-10", iso27001: "A.14.2.5", owasp2021: "A03:2021", owasp2017: "A1" },
  });

  // Final counts
  const totalCompliance = await prisma.complianceMapping.count();
  const totalSinks = await prisma.taintSink.count();
  const totalSources = await prisma.taintSource.count();
  const totalSanitizers = await prisma.taintSanitizer.count();
  const totalSecrets = await prisma.secretPattern.count();
  const totalIac = await prisma.iacRule.count();
  const grand = totalCompliance + totalSinks + totalSources + totalSanitizers + totalSecrets + totalIac;

  console.log("\n[SEED-TOP100] ✅ Complete!");
  console.log(`  Compliance Mappings: ${totalCompliance} CWEs`);
  console.log(`  Taint Sinks: ${totalSinks} (+${addedSinks} new)`);
  console.log(`  Taint Sources: ${totalSources}`);
  console.log(`  Taint Sanitizers: ${totalSanitizers}`);
  console.log(`  Secret Patterns: ${totalSecrets}`);
  console.log(`  IaC Rules: ${totalIac}`);
  console.log(`  GRAND TOTAL: ${grand} rules in DB`);
}

main().catch((e) => { console.error(e); process.exit(1); }).finally(() => prisma.$disconnect());

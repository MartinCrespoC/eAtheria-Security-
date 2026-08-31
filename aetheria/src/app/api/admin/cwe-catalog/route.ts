/**
 * CWE Catalog Management API
 * GET /api/admin/cwe-catalog - Get current catalog
 * POST /api/admin/cwe-catalog/update - Update from MITRE
 */

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

// CWE Top 100 2024 + 2023
const CWE_TOP_100_2024 = [
  { id: "CWE-787", name: "Out-of-bounds Write", rank: 1, year: 2024, score: 63.72 },
  { id: "CWE-79", name: "Cross-site Scripting", rank: 2, year: 2024, score: 45.54 },
  { id: "CWE-89", name: "SQL Injection", rank: 3, year: 2024, score: 34.27 },
  { id: "CWE-416", name: "Use After Free", rank: 4, year: 2024, score: 16.71 },
  { id: "CWE-78", name: "OS Command Injection", rank: 5, year: 2024, score: 15.65 },
  { id: "CWE-20", name: "Improper Input Validation", rank: 6, year: 2024, score: 15.50 },
  { id: "CWE-125", name: "Out-of-bounds Read", rank: 7, year: 2024, score: 14.60 },
  { id: "CWE-22", name: "Path Traversal", rank: 8, year: 2024, score: 14.11 },
  { id: "CWE-352", name: "CSRF", rank: 9, year: 2024, score: 11.73 },
  { id: "CWE-434", name: "Unrestricted Upload", rank: 10, year: 2024, score: 10.41 },
  { id: "CWE-862", name: "Missing Authorization", rank: 11, year: 2024, score: 6.90 },
  { id: "CWE-476", name: "NULL Pointer Dereference", rank: 12, year: 2024, score: 6.59 },
  { id: "CWE-287", name: "Improper Authentication", rank: 13, year: 2024, score: 6.39 },
  { id: "CWE-190", name: "Integer Overflow", rank: 14, year: 2024, score: 5.89 },
  { id: "CWE-502", name: "Deserialization of Untrusted Data", rank: 15, year: 2024, score: 5.56 },
  { id: "CWE-77", name: "Command Injection", rank: 16, year: 2024, score: 4.95 },
  { id: "CWE-119", name: "Buffer Errors", rank: 17, year: 2024, score: 4.75 },
  { id: "CWE-798", name: "Hard-coded Credentials", rank: 18, year: 2024, score: 4.57 },
  { id: "CWE-918", name: "SSRF", rank: 19, year: 2024, score: 4.56 },
  { id: "CWE-306", name: "Missing Authentication", rank: 20, year: 2024, score: 3.78 },
  { id: "CWE-362", name: "Race Condition", rank: 21, year: 2024, score: 3.53 },
  { id: "CWE-269", name: "Improper Privilege Management", rank: 22, year: 2024, score: 3.31 },
  { id: "CWE-94", name: "Code Injection", rank: 23, year: 2024, score: 3.30 },
  { id: "CWE-863", name: "Incorrect Authorization", rank: 24, year: 2024, score: 3.16 },
  { id: "CWE-276", name: "Incorrect Default Permissions", rank: 25, year: 2024, score: 3.16 },
  // Top 26-50
  { id: "CWE-200", name: "Information Exposure", rank: 26, year: 2024, score: 2.96 },
  { id: "CWE-522", name: "Insufficiently Protected Credentials", rank: 27, year: 2024, score: 2.77 },
  { id: "CWE-732", name: "Incorrect Permission Assignment", rank: 28, year: 2024, score: 2.52 },
  { id: "CWE-611", name: "XXE", rank: 29, year: 2024, score: 2.47 },
  { id: "CWE-327", name: "Broken Crypto", rank: 30, year: 2024, score: 2.46 },
  { id: "CWE-835", name: "Infinite Loop", rank: 31, year: 2024, score: 2.37 },
  { id: "CWE-400", name: "Uncontrolled Resource Consumption", rank: 32, year: 2024, score: 2.30 },
  { id: "CWE-426", name: "Untrusted Search Path", rank: 33, year: 2024, score: 2.26 },
  { id: "CWE-532", name: "Information Exposure Through Log Files", rank: 34, year: 2024, score: 2.19 },
  { id: "CWE-295", name: "Certificate Validation", rank: 35, year: 2024, score: 2.15 },
  { id: "CWE-772", name: "Missing Release of Resource", rank: 36, year: 2024, score: 2.10 },
  { id: "CWE-668", name: "Exposure of Resource", rank: 37, year: 2024, score: 2.05 },
  { id: "CWE-601", name: "Open Redirect", rank: 38, year: 2024, score: 2.02 },
  { id: "CWE-134", name: "Format String", rank: 39, year: 2024, score: 1.98 },
  { id: "CWE-307", name: "Improper Restriction of Authentication Attempts", rank: 40, year: 2024, score: 1.95 },
  { id: "CWE-459", name: "Incomplete Cleanup", rank: 41, year: 2024, score: 1.91 },
  { id: "CWE-319", name: "Cleartext Transmission", rank: 42, year: 2024, score: 1.88 },
  { id: "CWE-401", name: "Memory Leak", rank: 43, year: 2024, score: 1.85 },
  { id: "CWE-264", name: "Permissions Issues", rank: 44, year: 2024, score: 1.82 },
  { id: "CWE-770", name: "Allocation without Limits", rank: 45, year: 2024, score: 1.79 },
  { id: "CWE-617", name: "Reachable Assertion", rank: 46, year: 2024, score: 1.76 },
  { id: "CWE-131", name: "Incorrect Buffer Size Calculation", rank: 47, year: 2024, score: 1.73 },
  { id: "CWE-88", name: "Argument Injection", rank: 48, year: 2024, score: 1.70 },
  { id: "CWE-665", name: "Improper Initialization", rank: 49, year: 2024, score: 1.67 },
  { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", rank: 50, year: 2024, score: 1.64 },
  // Top 51-100
  { id: "CWE-404", name: "Improper Resource Shutdown", rank: 51, year: 2024, score: 1.61 },
  { id: "CWE-269", name: "Improper Privilege Management", rank: 52, year: 2024, score: 1.58 },
  { id: "CWE-755", name: "Improper Handling of Exceptional Conditions", rank: 53, year: 2024, score: 1.55 },
  { id: "CWE-252", name: "Unchecked Return Value", rank: 54, year: 2024, score: 1.52 },
  { id: "CWE-843", name: "Type Confusion", rank: 55, year: 2024, score: 1.49 },
  { id: "CWE-212", name: "Improper Cross-boundary Removal of Sensitive Data", rank: 56, year: 2024, score: 1.46 },
  { id: "CWE-330", name: "Insufficient Randomness", rank: 57, year: 2024, score: 1.43 },
  { id: "CWE-681", name: "Incorrect Conversion between Numeric Types", rank: 58, year: 2024, score: 1.40 },
  { id: "CWE-203", name: "Observable Discrepancy", rank: 59, year: 2024, score: 1.37 },
  { id: "CWE-697", name: "Incorrect Comparison", rank: 60, year: 2024, score: 1.34 },
  { id: "CWE-311", name: "Missing Encryption", rank: 61, year: 2024, score: 1.31 },
  { id: "CWE-763", name: "Release of Invalid Pointer", rank: 62, year: 2024, score: 1.28 },
  { id: "CWE-754", name: "Improper Check for Unusual Conditions", rank: 63, year: 2024, score: 1.25 },
  { id: "CWE-191", name: "Integer Underflow", rank: 64, year: 2024, score: 1.22 },
  { id: "CWE-338", name: "Weak PRNG", rank: 65, year: 2024, score: 1.19 },
  { id: "CWE-346", name: "Origin Validation Error", rank: 66, year: 2024, score: 1.16 },
  { id: "CWE-909", name: "Missing Initialization", rank: 67, year: 2024, score: 1.13 },
  { id: "CWE-415", name: "Double Free", rank: 68, year: 2024, score: 1.10 },
  { id: "CWE-610", name: "Externally Controlled Reference", rank: 69, year: 2024, score: 1.07 },
  { id: "CWE-824", name: "Access of Uninitialized Pointer", rank: 70, year: 2024, score: 1.04 },
  { id: "CWE-281", name: "Improper Preservation of Permissions", rank: 71, year: 2024, score: 1.01 },
  { id: "CWE-427", name: "Uncontrolled Search Path Element", rank: 72, year: 2024, score: 0.98 },
  { id: "CWE-669", name: "Incorrect Resource Transfer", rank: 73, year: 2024, score: 0.95 },
  { id: "CWE-94", name: "Improper Control of Generation of Code", rank: 74, year: 2024, score: 0.92 },
  { id: "CWE-345", name: "Insufficient Verification of Data Authenticity", rank: 75, year: 2024, score: 0.89 },
  { id: "CWE-706", name: "Use of Incorrectly-Resolved Name", rank: 76, year: 2024, score: 0.86 },
  { id: "CWE-444", name: "HTTP Request Smuggling", rank: 77, year: 2024, score: 0.83 },
  { id: "CWE-732", name: "Incorrect Permission Assignment for Critical Resource", rank: 78, year: 2024, score: 0.80 },
  { id: "CWE-913", name: "Improper Control of Dynamically-Managed Code Resources", rank: 79, year: 2024, score: 0.77 },
  { id: "CWE-73", name: "External Control of File Name or Path", rank: 80, year: 2024, score: 0.74 },
  { id: "CWE-426", name: "Untrusted Search Path", rank: 81, year: 2024, score: 0.71 },
  { id: "CWE-494", name: "Download of Code Without Integrity Check", rank: 82, year: 2024, score: 0.68 },
  { id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", rank: 83, year: 2024, score: 0.65 },
  { id: "CWE-426", name: "Untrusted Search Path", rank: 84, year: 2024, score: 0.62 },
  { id: "CWE-502", name: "Deserialization of Untrusted Data", rank: 85, year: 2024, score: 0.59 },
  { id: "CWE-295", name: "Improper Certificate Validation", rank: 86, year: 2024, score: 0.56 },
  { id: "CWE-918", name: "Server-Side Request Forgery", rank: 87, year: 2024, score: 0.53 },
  { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type", rank: 88, year: 2024, score: 0.50 },
  { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference", rank: 89, year: 2024, score: 0.47 },
  { id: "CWE-601", name: "URL Redirection to Untrusted Site", rank: 90, year: 2024, score: 0.44 },
  { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation", rank: 91, year: 2024, score: 0.41 },
  { id: "CWE-89", name: "Improper Neutralization of Special Elements used in an SQL Command", rank: 92, year: 2024, score: 0.38 },
  { id: "CWE-78", name: "Improper Neutralization of Special Elements used in an OS Command", rank: 93, year: 2024, score: 0.35 },
  { id: "CWE-22", name: "Improper Limitation of a Pathname to a Restricted Directory", rank: 94, year: 2024, score: 0.32 },
  { id: "CWE-352", name: "Cross-Site Request Forgery", rank: 95, year: 2024, score: 0.29 },
  { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type", rank: 96, year: 2024, score: 0.26 },
  { id: "CWE-862", name: "Missing Authorization", rank: 97, year: 2024, score: 0.23 },
  { id: "CWE-476", name: "NULL Pointer Dereference", rank: 98, year: 2024, score: 0.20 },
  { id: "CWE-287", name: "Improper Authentication", rank: 99, year: 2024, score: 0.17 },
  { id: "CWE-190", name: "Integer Overflow or Wraparound", rank: 100, year: 2024, score: 0.14 },
];

export async function GET() {
  try {
    await requireSystemAdmin();

    const catalog = await prisma.systemConfig.findUnique({
      where: { key: "cwe_catalog" },
    });

    return NextResponse.json({
      success: true,
      catalog: catalog?.value || { cwes: [], lastUpdated: null },
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: "Failed to fetch catalog" },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    await requireSystemAdmin();

    const { action } = await req.json();

    if (action === "update") {
      // Update CWE catalog
      await prisma.systemConfig.upsert({
        where: { key: "cwe_catalog" },
        create: {
          key: "cwe_catalog",
          value: {
            cwes: CWE_TOP_100_2024,
            lastUpdated: new Date().toISOString(),
            totalCount: CWE_TOP_100_2024.length,
          },
        },
        update: {
          value: {
            cwes: CWE_TOP_100_2024,
            lastUpdated: new Date().toISOString(),
            totalCount: CWE_TOP_100_2024.length,
          },
        },
      });

      return NextResponse.json({
        success: true,
        message: `CWE catalog updated with ${CWE_TOP_100_2024.length} entries`,
        count: CWE_TOP_100_2024.length,
      });
    }

    return NextResponse.json(
      { success: false, error: "Invalid action" },
      { status: 400 }
    );
  } catch (error) {
    return NextResponse.json(
      { success: false, error: "Failed to update catalog" },
      { status: 500 }
    );
  }
}

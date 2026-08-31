import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey } from "@/lib/api-auth";
import { prisma } from "@/lib/db";

interface CweCatalogEntry {
  id: string;
  name: string;
  rank?: number;
  year?: number;
  score?: number;
}

/**
 * Normalize a CWE identifier to the canonical "CWE-<n>" form.
 * Accepts "79", "cwe-79", "CWE-79", "cwe79", etc.
 */
function normalizeCweId(raw: string): string | null {
  const digits = raw.toUpperCase().replace(/[^0-9]/g, "");
  if (!digits) return null;
  return `CWE-${digits}`;
}

/**
 * GET /api/v1/cwe/:cweId
 * DB-driven CWE knowledge endpoint (no hardcoded data).
 *
 * Merges the compliance mapping (PCI-DSS / HIPAA / NIST 800-53 / ISO 27001 /
 * OWASP 2021+2017 / MITRE rank) from the `compliance_mappings` table with the
 * CWE name / rank / score from the `cwe_catalog` systemConfig, into a single
 * knowledge object plus a MITRE reference link.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ cweId: string }> }
) {
  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json(
      { error: "Invalid or expired API key. Provide: Authorization: Bearer aeth_xxx" },
      { status: 401 }
    );
  }

  const { cweId } = await params;
  const cwe = normalizeCweId(decodeURIComponent(cweId));
  if (!cwe) {
    return NextResponse.json({ error: "Invalid CWE id." }, { status: 400 });
  }

  const [mapping, catalogConfig] = await Promise.all([
    prisma.complianceMapping.findUnique({ where: { cwe } }),
    prisma.systemConfig.findUnique({ where: { key: "cwe_catalog" } }),
  ]);

  const catalogEntries =
    (catalogConfig?.value as { cwes?: CweCatalogEntry[] } | null)?.cwes ?? [];
  const catalogEntry = catalogEntries.find((e) => normalizeCweId(e.id) === cwe);

  if (!mapping && !catalogEntry) {
    return NextResponse.json(
      { error: `No knowledge found for ${cwe}.` },
      { status: 404 }
    );
  }

  const number = cwe.replace("CWE-", "");

  return NextResponse.json({
    cwe,
    name: catalogEntry?.name ?? null,
    mitreRank: catalogEntry?.rank ?? mapping?.mitreTop25 ?? null,
    mitreScore: catalogEntry?.score ?? null,
    catalogYear: catalogEntry?.year ?? null,
    compliance: {
      pciDss: mapping?.pciDss ?? null,
      hipaa: mapping?.hipaa ?? null,
      nist80053: mapping?.nist80053 ?? null,
      iso27001: mapping?.iso27001 ?? null,
      owasp2021: mapping?.owasp2021 ?? null,
      owasp2017: mapping?.owasp2017 ?? null,
      mitreTop25: mapping?.mitreTop25 ?? null,
    },
    references: {
      mitre: `https://cwe.mitre.org/data/definitions/${number}.html`,
      owasp: "https://owasp.org/Top10/",
    },
  });
}

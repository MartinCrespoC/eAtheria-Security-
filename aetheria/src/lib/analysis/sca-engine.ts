import { prisma } from "@/lib/db";

interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  severity: { type: string; score: string }[];
  affected: {
    package: { name: string; ecosystem: string };
    ranges: { type: string; events: { introduced?: string; fixed?: string }[] }[];
  }[];
  references: { type: string; url: string }[];
}

interface DependencyVuln {
  packageName: string;
  version: string;
  ecosystem: string;
  vulnId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  fixedVersion?: string;
  cveId?: string;
}

function cvssToSeverity(score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score >= 0.1) return "LOW";
  return "INFO";
}

export async function queryOsvApi(
  packageName: string,
  version: string,
  ecosystem: string
): Promise<OsvVulnerability[]> {
  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name: packageName, ecosystem },
        version,
      }),
    });

    if (!res.ok) return [];
    const data = await res.json();
    return data.vulns || [];
  } catch {
    console.error(`OSV query failed for ${packageName}@${version}`);
    return [];
  }
}

export async function runScaAnalysis(
  analysisId: string,
  dependencies: { name: string; version: string; ecosystem: string }[]
): Promise<DependencyVuln[]> {
  const allVulns: DependencyVuln[] = [];

  for (const dep of dependencies) {
    const osvVulns = await queryOsvApi(dep.name, dep.version, dep.ecosystem);

    for (const osv of osvVulns) {
      let score = 5.0;
      if (osv.severity?.length > 0) {
        const cvss = osv.severity.find((s) => s.type === "CVSS_V3");
        if (cvss) score = parseFloat(cvss.score);
      }

      let fixedVersion: string | undefined;
      const affected = osv.affected?.[0];
      if (affected?.ranges) {
        for (const range of affected.ranges) {
          const fixEvent = range.events?.find((e) => e.fixed);
          if (fixEvent?.fixed) {
            fixedVersion = fixEvent.fixed;
            break;
          }
        }
      }

      const cveRef = osv.references?.find((r) => r.url?.includes("cve.org") || r.url?.includes("nvd.nist.gov"));
      const cveId = osv.id.startsWith("CVE-") ? osv.id : cveRef?.url?.match(/CVE-\d+-\d+/)?.[0];

      const vuln: DependencyVuln = {
        packageName: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        vulnId: osv.id,
        severity: cvssToSeverity(score),
        title: osv.summary || `Vulnerability in ${dep.name}`,
        description: osv.details || osv.summary || "",
        fixedVersion,
        cveId: cveId || undefined,
      };

      allVulns.push(vuln);

      // Store in DB with full SCA metadata
      await prisma.vulnerability.create({
        data: {
          severity: vuln.severity,
          confidence: "HIGH",
          category: "Dependency",
          title: vuln.title,
          description: `${vuln.description}${fixedVersion ? `\n\nFixed version: ${fixedVersion}` : ""}`,
          cveId: vuln.cveId,
          smartFix: fixedVersion
            ? `Update ${dep.name} from ${dep.version} to ${fixedVersion}`
            : `Review and update ${dep.name} to a non-vulnerable version`,
          fixExplanation: fixedVersion
            ? `Version ${fixedVersion} contains the security patch for ${osv.id}. Update your dependency to resolve this vulnerability.`
            : `No fixed version identified. Monitor ${dep.name} for security updates or consider alternative packages.`,
          detectionMethod: "SCA",
          packageName: dep.name,
          packageVersion: dep.version,
          ecosystem: dep.ecosystem,
          rootCause: `Vulnerable dependency version (${dep.name}@${dep.version}) with known ${osv.id}`,
          analysisId,
        },
      });
    }
  }

  return allVulns;
}

export function parseDependencies(
  content: string,
  filename: string
): { name: string; version: string; ecosystem: string }[] {
  const deps: { name: string; version: string; ecosystem: string }[] = [];

  if (filename === "package.json" || filename.endsWith("/package.json")) {
    try {
      const pkg = JSON.parse(content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };
      for (const [name, ver] of Object.entries(allDeps)) {
        const version = String(ver).replace(/^[\^~>=<]+/, "");
        deps.push({ name, version, ecosystem: "npm" });
      }
    } catch {
      // Invalid JSON
    }
  }

  if (filename === "requirements.txt" || filename.endsWith("/requirements.txt")) {
    const lines = content.split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)==(.+)$/);
      if (match) {
        deps.push({ name: match[1], version: match[2], ecosystem: "PyPI" });
      }
    }
  }

  if (filename === "pom.xml" || filename.endsWith("/pom.xml")) {
    const regex = /<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
      deps.push({
        name: `${match[1]}:${match[2]}`,
        version: match[3],
        ecosystem: "Maven",
      });
    }
  }

  return deps;
}

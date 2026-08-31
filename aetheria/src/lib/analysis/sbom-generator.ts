/**
 * SBOM Generator - CycloneDX format
 * Generates Software Bill of Materials from parsed dependencies
 */

interface SbomComponent {
  type: string;
  name: string;
  version: string;
  purl: string;
}

interface CycloneDXSbom {
  bomFormat: string;
  specVersion: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { name: string; version: string }[];
    component: { type: string; name: string; version: string };
  };
  components: SbomComponent[];
}

const ECOSYSTEM_PURL_MAP: Record<string, string> = {
  npm: "pkg:npm",
  pypi: "pkg:pypi",
  maven: "pkg:maven",
  cargo: "pkg:cargo",
  go: "pkg:golang",
  rubygems: "pkg:gem",
  nuget: "pkg:nuget",
};

/**
 * Generate a CycloneDX SBOM from a list of dependencies
 */
export function generateSbom(
  dependencies: { name: string; version: string; ecosystem: string }[],
  appName: string = "application",
  appVersion: string = "1.0.0"
): CycloneDXSbom {
  const components: SbomComponent[] = dependencies.map((dep) => {
    const purlPrefix = ECOSYSTEM_PURL_MAP[dep.ecosystem.toLowerCase()] || `pkg:${dep.ecosystem.toLowerCase()}`;
    return {
      type: "library",
      name: dep.name,
      version: dep.version,
      purl: `${purlPrefix}/${dep.name}@${dep.version}`,
    };
  });

  // Deduplicate by purl
  const seen = new Set<string>();
  const uniqueComponents = components.filter((c) => {
    if (seen.has(c.purl)) return false;
    seen.add(c.purl);
    return true;
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ name: "EATHERIA Security", version: "1.0.0" }],
      component: {
        type: "application",
        name: appName,
        version: appVersion,
      },
    },
    components: uniqueComponents,
  };
}

/**
 * Generate SBOM and return as JSON string for storage
 */
export function generateSbomJson(
  dependencies: { name: string; version: string; ecosystem: string }[],
  appName?: string,
  appVersion?: string
): string {
  const sbom = generateSbom(dependencies, appName, appVersion);
  return JSON.stringify(sbom, null, 2);
}

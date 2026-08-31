import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect, notFound } from "next/navigation";
import { AnalysisResultsEnterprise } from "@/components/dashboard/analysis-results-enterprise";
import { AnalysisLive } from "@/components/dashboard/analysis-live";

const IN_PROGRESS_STATUSES = ["PENDING", "INITIALIZING", "SCANNING", "VALIDATING"];

export default async function AnalysisDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await auth();
  if (!session?.user?.companyId) redirect("/login");

  const { id } = await params;

  const analysis = await prisma.analysis.findFirst({
    where: {
      id,
      appVersion: { application: { companyId: session.user.companyId } },
    },
    include: {
      appVersion: {
        include: {
          application: { select: { id: true, name: true, slug: true, language: true, company: { select: { showInfoFindings: true } } } },
        },
      },
      vulnerabilities: {
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
      },
    },
  });

  if (!analysis) notFound();

  // Show real-time progress for in-progress analyses
  if (IN_PROGRESS_STATUSES.includes(analysis.status)) {
    return (
      <div className="space-y-6">
        <AnalysisLive
          analysisId={analysis.id}
          appName={analysis.appVersion.application.name}
          appId={analysis.appVersion.application.id}
          version={analysis.appVersion.version}
        />
      </div>
    );
  }

  // Batch-load knowledge for all CWE IDs in findings
  const cweIds = [...new Set(analysis.vulnerabilities.map((v) => v.cweId).filter(Boolean))] as string[];

  const [complianceMappings, catalogEntries, huntSkillCwes] = await Promise.all([
    cweIds.length > 0 ? prisma.complianceMapping.findMany({ where: { cwe: { in: cweIds } } }) : Promise.resolve([]),
    cweIds.length > 0 ? prisma.vulnerabilityCatalog.findMany({
      where: { cweId: { in: cweIds } },
      select: { cweId: true, name: true, remediation: true, references: true, rank: true, year: true },
    }) : Promise.resolve([]),
    cweIds.length > 0 ? prisma.huntSkillCwe.findMany({
      where: { cweId: { in: cweIds }, skill: { isActive: true } },
      include: { skill: { select: { slug: true, name: true, reportCount: true, rootCauses: true, impactExamples: true, validationGate: true, chains: true } } },
    }) : Promise.resolve([]),
  ]);

  // Build knowledgeMap: Record<cweId, KnowledgeEntry>
  const knowledgeMap: Record<string, {
    compliance: Record<string, unknown> | null;
    catalog: Record<string, unknown> | null;
    skills: { slug: string; name: string; reportCount: number }[];
    rootCauses: { title: string; detail: string }[];
    impactExamples: { scenario: string; description: string; cveIds: string[] }[];
    validationGate: { question: string; criteria: string }[];
    chains: { targetSkill: string; primitive: string }[];
  }> = {};

  for (const cweId of cweIds) {
    const compliance = complianceMappings.find((c) => c.cwe === cweId) || null;
    const catalog = catalogEntries.find((c) => c.cweId === cweId) || null;
    const skillMappings = huntSkillCwes.filter((s) => s.cweId === cweId);

    const rootCauses: { title: string; detail: string }[] = [];
    const impactExamples: { scenario: string; description: string; cveIds: string[] }[] = [];
    const validationGate: { question: string; criteria: string }[] = [];
    const chains: { targetSkill: string; primitive: string }[] = [];

    for (const sm of skillMappings) {
      const rc = sm.skill.rootCauses as { title: string; detail: string }[] | null;
      if (rc) rootCauses.push(...rc);
      const ie = sm.skill.impactExamples as { scenario: string; description: string; cveIds: string[] }[] | null;
      if (ie) impactExamples.push(...ie);
      const vg = sm.skill.validationGate as { question: string; criteria: string }[] | null;
      if (vg) validationGate.push(...vg);
      const ch = sm.skill.chains as { targetSkill: string; primitive: string }[] | null;
      if (ch) chains.push(...ch);
    }

    knowledgeMap[cweId] = {
      compliance: compliance ? {
        pciDss: compliance.pciDss,
        hipaa: compliance.hipaa,
        nist80053: compliance.nist80053,
        iso27001: compliance.iso27001,
        owasp2021: compliance.owasp2021,
        owasp2017: compliance.owasp2017,
        mitreTop25: compliance.mitreTop25,
      } : null,
      catalog: catalog ? {
        name: catalog.name,
        remediation: catalog.remediation,
        references: catalog.references,
        rank: catalog.rank,
        year: catalog.year,
      } : null,
      skills: skillMappings.map((sm) => ({ slug: sm.skill.slug, name: sm.skill.name, reportCount: sm.skill.reportCount })),
      rootCauses: rootCauses.slice(0, 10),
      impactExamples: impactExamples.slice(0, 8),
      validationGate: validationGate.slice(0, 7),
      chains: chains.slice(0, 8),
    };
  }

  // Serialize for client component (handle BigInt + new fields)
  const serializedAnalysis = {
    ...analysis,
    inputTokens: Number(analysis.inputTokens),
    outputTokens: Number(analysis.outputTokens),
    estimatedCost: analysis.estimatedCost ? Number(analysis.estimatedCost) : null,
    appVersion: {
      ...analysis.appVersion,
      fileSize: analysis.appVersion.fileSize ? Number(analysis.appVersion.fileSize) : null,
    },
    vulnerabilities: analysis.vulnerabilities.map((v) => ({
      ...v,
      fpReason: (v as Record<string, unknown>).fpReason || null,
      rootCause: (v as Record<string, unknown>).rootCause || null,
      packageName: (v as Record<string, unknown>).packageName || null,
      packageVersion: (v as Record<string, unknown>).packageVersion || null,
      ecosystem: (v as Record<string, unknown>).ecosystem || null,
    })),
  };

  return (
    <div className="space-y-6">
      <AnalysisResultsEnterprise
        analysis={JSON.parse(JSON.stringify(serializedAnalysis))}
        knowledgeMap={knowledgeMap}
        showInfoFindings={analysis.appVersion.application.company.showInfoFindings}
      />
    </div>
  );
}

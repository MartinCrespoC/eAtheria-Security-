import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { redirect } from "next/navigation";
import { ScansList } from "./scans-list";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const session = await auth();
  if (!session?.user) redirect("/login");

  const companyId = session.user.companyId;

  const [analyses, queueJobs] = await Promise.all([
    prisma.analysis.findMany({
      where: companyId
        ? { appVersion: { application: { companyId } } }
        : undefined,
      include: {
        appVersion: {
          include: {
            application: {
              select: { id: true, name: true, slug: true },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
      take: 100,
    }),
    prisma.queueJob.findMany({
      where: companyId ? { companyId, type: "scan" } : undefined,
      orderBy: { createdAt: "desc" },
      take: 50,
    }),
  ]);

  // Merge queue jobs with analyses for a unified view
  const scans = analyses.map((a) => ({
    id: a.id,
    status: a.status,
    createdAt: a.createdAt,
    completedAt: a.completedAt,
    duration: a.duration,
    totalIssues: a.totalIssues,
    criticalCount: a.criticalCount,
    highCount: a.highCount,
    mediumCount: a.mediumCount,
    lowCount: a.lowCount,
    scanTypes: a.scanTypes as string[] | Record<string, unknown>,
    appName: a.appVersion.application.name,
    appSlug: a.appVersion.application.slug,
    version: a.appVersion.version,
    branch: a.appVersion.branch,
    source: "analysis",
  }));

  // Add pending queue jobs that don't have an analysis yet
  const queuedJobs = queueJobs
    .filter((j) => j.status === "pending" || j.status === "processing")
    .map((j) => ({
      id: j.id,
      status: j.status === "processing" ? "SCANNING" : "PENDING",
      createdAt: j.createdAt,
      completedAt: null,
      duration: null,
      totalIssues: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      scanTypes: [] as string[],
      appName: "Queued Scan",
      appSlug: "",
      version: "",
      branch: null,
      source: "queue",
    }));

  const allScans = [...scans, ...queuedJobs].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Security Scans</h1>
        <p className="text-text-secondary mt-1">
          Monitor all security scans across your applications
        </p>
      </div>
      <ScansList scans={allScans} />
    </div>
  );
}

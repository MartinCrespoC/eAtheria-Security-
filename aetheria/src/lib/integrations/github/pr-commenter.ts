import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/crypto";
import { Octokit } from "octokit";

/**
 * Post scan results as a comment on a GitHub Pull Request.
 * Formats vulnerabilities as a markdown table with severity counts.
 */
export async function postScanResults(
  connectionId: string,
  prNumber: number,
  repoFullName: string,
  analysisId: string
): Promise<void> {
  // Fetch connection to get access token
  const connection = await prisma.githubConnection.findUnique({
    where: { id: connectionId },
  });

  if (!connection) {
    throw new Error(`GitHub connection ${connectionId} not found`);
  }

  // Fetch analysis with vulnerabilities
  const analysis = await prisma.analysis.findUnique({
    where: { id: analysisId },
    include: {
      vulnerabilities: {
        orderBy: { severity: "asc" },
        take: 50, // Limit to avoid huge comments
      },
      appVersion: {
        include: { application: { select: { name: true } } },
      },
    },
  });

  if (!analysis) {
    throw new Error(`Analysis ${analysisId} not found`);
  }

  const comment = formatAnalysisComment(analysis);

  // Post comment using Octokit
  const accessToken = decrypt(connection.accessToken);
  const octokit = new Octokit({ auth: accessToken });

  const [owner, repo] = repoFullName.split("/");

  await octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: prNumber,
    body: comment,
  });
}

function formatAnalysisComment(analysis: {
  status: string;
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  duration: number | null;
  vulnerabilities: Array<{
    severity: string;
    title: string;
    category: string;
    filePath: string | null;
    lineStart: number | null;
    cweId: string | null;
    smartFix: string | null;
  }>;
  appVersion: { application: { name: string }; version: string };
}): string {
  const statusEmoji = analysis.status === "COMPLETED" ? "✅" : "❌";
  const dashboardUrl = process.env.NEXT_PUBLIC_APP_URL || "https://app.aetheria.io";

  let comment = `## ${statusEmoji} EATHERIA Security Scan Results\n\n`;

  comment += `**Application:** ${analysis.appVersion.application.name}  \n`;
  comment += `**Version:** ${analysis.appVersion.version}  \n`;
  comment += `**Status:** ${analysis.status}  \n`;
  if (analysis.duration) comment += `**Duration:** ${analysis.duration}s  \n`;
  comment += "\n";

  // Summary table
  comment += `### Summary\n\n`;
  comment += `| Severity | Count |\n`;
  comment += `|----------|-------|\n`;
  comment += `| 🔴 Critical | ${analysis.criticalCount} |\n`;
  comment += `| 🟠 High | ${analysis.highCount} |\n`;
  comment += `| 🟡 Medium | ${analysis.mediumCount} |\n`;
  comment += `| 🔵 Low | ${analysis.lowCount} |\n`;
  comment += `| ⚪ Info | ${analysis.infoCount} |\n`;
  comment += `| **Total** | **${analysis.totalIssues}** |\n\n`;

  // Vulnerability details
  if (analysis.vulnerabilities.length > 0) {
    comment += `### Vulnerabilities Found\n\n`;
    comment += `| # | Severity | Title | Category | Location | CWE |\n`;
    comment += `|---|----------|-------|----------|----------|-----|\n`;

    analysis.vulnerabilities.forEach((vuln, idx) => {
      const location = vuln.filePath
        ? `${vuln.filePath}${vuln.lineStart ? `:${vuln.lineStart}` : ""}`
        : "-";
      comment += `| ${idx + 1} | ${vuln.severity} | ${vuln.title} | ${vuln.category} | \`${location}\` | ${vuln.cweId || "-"} |\n`;
    });

    if (analysis.totalIssues > 50) {
      comment += `\n*... and ${analysis.totalIssues - 50} more issues. [View full report](${dashboardUrl}/dashboard/analyses)*\n`;
    }
  }

  comment += `\n---\n`;
  comment += `*Powered by [EATHERIA Security Platform](${dashboardUrl})*\n`;

  return comment;
}

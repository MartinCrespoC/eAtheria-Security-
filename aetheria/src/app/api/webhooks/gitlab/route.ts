import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifyToken, parseEvent } from "@/lib/integrations/gitlab/webhook-handler";
import { triggerMRScan } from "@/lib/integrations/gitlab/mr-scanner";
import { enqueueScan } from "@/lib/queue";

/**
 * GitLab Webhook Handler
 * Receives webhook events from GitLab and triggers security scans.
 */
export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    const gitlabToken = request.headers.get("x-gitlab-token");
    const eventType = request.headers.get("x-gitlab-event");

    if (!eventType) {
      return NextResponse.json({ error: "Missing X-Gitlab-Event header" }, { status: 400 });
    }

    let body: Record<string, unknown>;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const event = parseEvent(request.headers, body);
    if (!event) {
      return NextResponse.json({ error: "Could not parse event" }, { status: 400 });
    }

    // Look up GitlabConnection by project path or URL
    const projectPath = event.project.pathWithNamespace;
    const connections = await prisma.gitlabConnection.findMany({
      where: {
        OR: [
          { projectUrl: { contains: projectPath } },
          { name: projectPath },
        ],
      },
    });

    if (connections.length === 0) {
      console.warn(`[WEBHOOK] Unknown GitLab project: ${projectPath}`);
      return NextResponse.json({ ok: true, message: "Project not registered" });
    }

    // Find the right connection (verify token if available)
    let connection = connections[0];
    if (connections.length > 1) {
      // Try to match by webhook token
      for (const conn of connections) {
        if (conn.webhookToken && gitlabToken === conn.webhookToken) {
          connection = conn;
          break;
        }
      }
    }

    // Verify webhook token if configured
    if (connection.webhookToken) {
      if (!verifyToken(request.headers, connection.webhookToken)) {
        console.warn(`[WEBHOOK] Invalid GitLab token for project: ${projectPath}`);
        return NextResponse.json({ error: "Invalid token" }, { status: 401 });
      }
    }

    const projectId = String(event.project.id);

    // Handle Merge Request events
    if ((eventType === "Merge Request Hook" || event.action === "merge_request") && event.mr) {
      const action = (body.object_attributes as Record<string, unknown>)?.action as string;
      if ((action === "open" || action === "update") && connection.autoScanOnMR) {
        triggerMRScan(
          connection.id,
          event.mr.iid,
          event.mr.sourceBranch,
          projectId,
          event.mr.sha
        ).catch((err) => console.error("[WEBHOOK] MR scan trigger failed:", err));
      }
    }

    // Handle Push events
    if ((eventType === "Push Hook" || event.action === "push") && connection.autoScanOnPush && event.branch && event.sha) {
      const appSlug = projectId.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
      const application = await prisma.application.findFirst({
        where: { companyId: connection.companyId, slug: appSlug },
      });

      if (application) {
        const versionTag = `push-${event.branch}-${event.sha.slice(0, 7)}`;
        let version = await prisma.appVersion.findFirst({
          where: { applicationId: application.id, version: versionTag },
        });

        if (!version) {
          version = await prisma.appVersion.create({
            data: {
              version: versionTag,
              branch: event.branch,
              commitHash: event.sha,
              sourceType: "URL",
              sourceUrl: `${connection.projectUrl}/-/tree/${event.sha}`,
              applicationId: application.id,
            },
          });
        }

        enqueueScan({
          applicationId: application.id,
          versionId: version.id,
          companyId: connection.companyId,
          scanTypes: ["sast", "sca"],
          source: "gitlab",
          metadata: {
            headSha: event.sha,
            branch: event.branch,
            connectionId: connection.id,
            projectId,
          },
        }).catch((err) => console.error("[WEBHOOK] GitLab push scan enqueue failed:", err));
      }
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("[WEBHOOK] GitLab webhook error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

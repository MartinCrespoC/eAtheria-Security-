import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { verifySignature, parseEvent } from "@/lib/integrations/github/webhook-handler";
import { triggerPRScan } from "@/lib/integrations/github/pr-scanner";
import { enqueueScan } from "@/lib/queue";

/**
 * GitHub Webhook Handler
 * Receives webhook events from GitHub and triggers security scans.
 */
export async function POST(request: NextRequest) {
  try {
    // Get raw body for signature verification
    const rawBody = await request.text();
    const signature = request.headers.get("x-hub-signature-256");
    const eventType = request.headers.get("x-github-event");

    if (!eventType) {
      return NextResponse.json({ error: "Missing X-GitHub-Event header" }, { status: 400 });
    }

    // Parse the body
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

    // Look up GithubConnection by repo full_name
    const repo = await prisma.githubRepository.findFirst({
      where: { fullName: event.repo.fullName },
      include: {
        connection: {
          select: {
            id: true,
            webhookSecret: true,
            webhookEnabled: true,
            autoScanOnPR: true,
            autoScanOnPush: true,
          },
        },
      },
    });

    if (!repo) {
      // Repo not registered — still return 200 to avoid GitHub retries
      console.warn(`[WEBHOOK] Unknown repo: ${event.repo.fullName}`);
      return NextResponse.json({ ok: true, message: "Repo not registered" });
    }

    const connection = repo.connection;

    // Verify webhook signature if secret is configured
    if (connection.webhookSecret) {
      if (!verifySignature(rawBody, signature, connection.webhookSecret)) {
        console.warn(`[WEBHOOK] Invalid signature for repo: ${event.repo.fullName}`);
        return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
      }
    }

    // Handle pull_request events
    if (event.type === "pull_request" && event.pr) {
      const action = event.action;
      if ((action === "opened" || action === "synchronize") && connection.autoScanOnPR) {
        // Fire and forget — don't block the webhook response
        triggerPRScan(
          connection.id,
          event.pr.number,
          event.pr.headSha,
          event.repo.fullName,
          event.pr.headRef
        ).catch((err) => console.error("[WEBHOOK] PR scan trigger failed:", err));
      }
    }

    // Handle push events
    if (event.type === "push" && connection.autoScanOnPush && event.branch && event.sha) {
      // Create a version and enqueue scan for push
      const appSlug = event.repo.fullName.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
      const application = await prisma.application.findFirst({
        where: { companyId: repo.connectionId, slug: appSlug },
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
              sourceType: "GITHUB",
              sourceUrl: `https://github.com/${event.repo.fullName}/tree/${event.sha}`,
              applicationId: application.id,
            },
          });
        }

        enqueueScan({
          applicationId: application.id,
          versionId: version.id,
          companyId: repo.connectionId,
          scanTypes: ["sast", "sca"],
          source: "github",
          metadata: {
            headSha: event.sha,
            branch: event.branch,
            repoFullName: event.repo.fullName,
            connectionId: connection.id,
          },
        }).catch((err) => console.error("[WEBHOOK] Push scan enqueue failed:", err));
      }
    }

    // Always return 200 quickly to prevent GitHub retries
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("[WEBHOOK] GitHub webhook error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

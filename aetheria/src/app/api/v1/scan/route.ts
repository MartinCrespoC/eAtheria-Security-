import { NextRequest, NextResponse } from "next/server";
import { authenticateApiKey, hasScope } from "@/lib/api-auth";
import { prisma } from "@/lib/db";
import { rateLimit, getClientIp } from "@/lib/rate-limit";
import { isSafeExternalUrl } from "@/lib/security/url-guard";
import { triggerAnalysis } from "@/lib/analysis/trigger";
import * as fs from "fs";
import * as path from "path";
import { cleanupOldVersionUploads } from "@/lib/upload-cleanup";

// Max decoded source archive size (1 GB) to protect the server.
const MAX_SOURCE_BYTES = 1024 * 1024 * 1024;

/**
 * Extract a ZIP buffer into uploads/{versionId} so triggerAnalysis can read it.
 * Reuses the same AdmZip approach as /api/scan/upload.
 */
async function extractSourceZip(versionId: string, zipBuffer: Buffer): Promise<void> {
  const uploadDir = path.join(process.cwd(), "uploads", versionId);
  await fs.promises.mkdir(uploadDir, { recursive: true });
  const zipPath = path.join(uploadDir, "source.zip");
  await fs.promises.writeFile(zipPath, zipBuffer);
  try {
    const AdmZip = (await import("adm-zip")).default;
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(uploadDir, true);
  } finally {
    await fs.promises.unlink(zipPath).catch(() => {});
  }
}

/**
 * POST /api/v1/scan
 * Public API endpoint for CI/CD integrations (GitHub Actions, GitLab CI, etc.)
 *
 * Headers:
 *   Authorization: Bearer aeth_xxxxx
 *
 * Body:
 *   {
 *     "repository": "owner/repo",
 *     "branch": "main",
 *     "commit": "abc123",
 *     "scanTypes": ["sast", "sca"],  // optional, defaults to ["sast", "sca"]
 *     "code": "base64-encoded-zip",   // or provide via sourceUrl
 *     "sourceUrl": "https://...",     // alternative to code
 *     "pullRequest": {               // optional: PR context for comments/fixes
 *       "number": 42,
 *       "title": "Add login feature",
 *       "baseBranch": "main"
 *     }
 *   }
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);

  // Rate limit: 60 requests per minute per API key
  const rl = rateLimit(`api:scan:${ip}`, { maxRequests: 60, windowMs: 60_000 });
  if (!rl.success) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Max 60 requests/minute." },
      { status: 429 }
    );
  }

  // Authenticate via API key
  const ctx = await authenticateApiKey(req);
  if (!ctx) {
    return NextResponse.json(
      { error: "Invalid or expired API key. Provide: Authorization: Bearer aeth_xxx" },
      { status: 401 }
    );
  }

  if (!hasScope(ctx, "analysis:create")) {
    return NextResponse.json(
      { error: "API key does not have 'analysis:create' scope." },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const {
      repository,
      branch,
      commit,
      scanTypes = ["sast", "sca"],
      pullRequest,
      code,
      sourceUrl,
    } = body;

    if (!repository) {
      return NextResponse.json(
        { error: "Field 'repository' is required." },
        { status: 400 }
      );
    }

    // Individual mode: no licensing limits

    // Find or create application for this repository
    const parts = (repository as string).split("/");
    const appName = parts.length > 1 ? parts[1] : repository;

    let application = await prisma.application.findFirst({
      where: {
        companyId: ctx.companyId,
        name: appName,
      },
    });

    if (!application) {
      application = await prisma.application.create({
        data: {
          name: appName,
          slug: appName.toLowerCase().replace(/[^a-z0-9-]/g, "-"),
          repoUrl: `https://github.com/${repository}`,
          companyId: ctx.companyId,
        },
      });
    }

    // Create or find app version for this branch/commit
    const versionTag = commit ? `${branch}@${commit.slice(0, 7)}` : branch || "main";

    let appVersion = await prisma.appVersion.findFirst({
      where: {
        applicationId: application.id,
        version: versionTag,
      },
    });

    if (!appVersion) {
      appVersion = await prisma.appVersion.create({
        data: {
          version: versionTag,
          branch: branch || "main",
          commitHash: commit || null,
          sourceType: "GITHUB",
          applicationId: application.id,
        },
      });
    }

    // Ingest source code so the analysis engine has something to scan.
    // Priority: base64 zip in `code` -> fetch `sourceUrl` -> nothing (engine
    // will report no source). This is what makes CI/CD repo scans actually work.
    let sourceIngested = false;
    if (code && typeof code === "string") {
      const zipBuffer = Buffer.from(code, "base64");
      if (zipBuffer.length > MAX_SOURCE_BYTES) {
        return NextResponse.json(
          { error: `Source archive too large (max ${MAX_SOURCE_BYTES / 1024 / 1024} MB decoded).` },
          { status: 400 }
        );
      }
      try {
        await extractSourceZip(appVersion.id, zipBuffer);
        sourceIngested = true;
      } catch (extractErr) {
        console.error("Source extraction failed:", extractErr);
        return NextResponse.json(
          { error: "Failed to extract source archive. Ensure 'code' is a valid base64-encoded ZIP." },
          { status: 400 }
        );
      }
    } else if (sourceUrl && typeof sourceUrl === "string") {
      // SSRF guard: only public http(s) URLs may be fetched server-side
      if (!isSafeExternalUrl(sourceUrl)) {
        return NextResponse.json(
          { error: "sourceUrl must be a public http(s) URL." },
          { status: 400 }
        );
      }
      try {
        // redirect:manual prevents open-redirect bypass of the guard
        const res = await fetch(sourceUrl, { redirect: "manual" });
        if (res.status >= 300 && res.status < 400) {
          return NextResponse.json(
            { error: "sourceUrl redirects are not allowed." },
            { status: 400 }
          );
        }
        if (!res.ok) {
          return NextResponse.json(
            { error: `Failed to fetch sourceUrl (${res.status}).` },
            { status: 400 }
          );
        }
        const buf = Buffer.from(await res.arrayBuffer());
        if (buf.length > MAX_SOURCE_BYTES) {
          return NextResponse.json(
            { error: `Source archive too large (max ${MAX_SOURCE_BYTES / 1024 / 1024} MB).` },
            { status: 400 }
          );
        }
        await extractSourceZip(appVersion.id, buf);
        sourceIngested = true;
      } catch (fetchErr) {
        console.error("sourceUrl fetch failed:", fetchErr);
        return NextResponse.json(
          { error: "Failed to fetch/extract sourceUrl." },
          { status: 400 }
        );
      }
    }

    // Purge extracted sources from previous versions of this application so a new
    // upload replaces the old one on disk (DB records are preserved).
    if (sourceIngested) {
      await cleanupOldVersionUploads(application.id, appVersion.id).catch((err) =>
        console.error("Old version upload cleanup failed:", err)
      );
    }

    // Create analysis record
    const analysis = await prisma.analysis.create({
      data: {
        status: "PENDING",
        scanTypes: scanTypes,
        aiValidation: true,
        appVersionId: appVersion.id,
        triggeredBy: `api:${ctx.apiKeyId}`,
      },
    });

    // Trigger async analysis engine
    triggerAnalysis(analysis.id).catch(console.error);

    return NextResponse.json(
      {
        id: analysis.id,
        status: "PENDING",
        repository,
        branch: branch || "main",
        commit: commit || null,
        scanTypes,
        pullRequest: pullRequest || null,
        sourceIngested,
        statusUrl: `/api/v1/scan/${analysis.id}`,
        message: sourceIngested
          ? "Analysis queued successfully. Poll statusUrl for results."
          : "Analysis queued, but no source code was provided (send 'code' as a base64 ZIP or 'sourceUrl'). The scan will have no findings.",
      },
      { status: 202 }
    );
  } catch (error) {
    console.error("CI/CD scan error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

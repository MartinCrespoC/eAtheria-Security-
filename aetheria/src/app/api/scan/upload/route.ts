import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { hashApiKey } from "@/lib/crypto";
import { enqueueScan } from "@/lib/queue";
import { cleanupOldVersionUploads } from "@/lib/upload-cleanup";
import {
  extractArchiveSafely,
  UnsafeArchiveError,
} from "@/lib/upload/safe-extract";

/**
 * POST /api/scan/upload
 * Public API endpoint for CI/CD integration.
 * Accepts ZIP with API key auth (X-API-Key header).
 * Auto-creates Application + Version and enqueues scan.
 */
export async function POST(request: NextRequest) {
  try {
    // Validate API key
    const apiKey = request.headers.get("x-api-key");
    if (!apiKey) {
      return NextResponse.json({ error: "Missing X-API-Key header" }, { status: 401 });
    }

    const keyHash = hashApiKey(apiKey);
    const apiKeyRecord = await prisma.apiKey.findUnique({
      where: { keyHash },
      include: { company: { select: { id: true, isActive: true } } },
    });

    if (!apiKeyRecord || !apiKeyRecord.isActive) {
      return NextResponse.json({ error: "Invalid or inactive API key" }, { status: 401 });
    }

    if (!apiKeyRecord.company?.isActive) {
      return NextResponse.json({ error: "Company is inactive" }, { status: 403 });
    }

    // Check scopes
    if (!(apiKeyRecord.scopes as string[]).includes("analysis:create")) {
      return NextResponse.json({ error: "API key lacks analysis:create scope" }, { status: 403 });
    }

    // Update last used
    await prisma.apiKey.update({
      where: { id: apiKeyRecord.id },
      data: { lastUsedAt: new Date() },
    });

    const companyId = apiKeyRecord.companyId;

    // Parse form data (expecting file + optional metadata)
    const formData = await request.formData();
    const file = formData.get("file") as File | null;
    const appName = (formData.get("appName") as string) || "api-upload";
    const branch = (formData.get("branch") as string) || "main";
    const commitHash = (formData.get("commitHash") as string) || undefined;
    const scanTypesParam = (formData.get("scanTypes") as string) || "sast,sca";

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // Get or create application
    const appSlug = appName.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
    let application = await prisma.application.findFirst({
      where: { companyId, slug: appSlug },
    });

    if (!application) {
      application = await prisma.application.create({
        data: {
          name: appName,
          slug: appSlug,
          companyId,
        },
      });
    }

    // Create version
    const timestamp = Date.now();
    const version = await prisma.appVersion.create({
      data: {
        version: `api-${timestamp}`,
        branch,
        commitHash,
        sourceType: "ZIP_UPLOAD",
        applicationId: application.id,
      },
    });

    // Save uploaded file to disk and extract
    const fs = await import("fs/promises");
    const path = await import("path");
    const uploadDir = path.join(process.cwd(), "uploads", version.id);
    await fs.mkdir(uploadDir, { recursive: true });

    const buffer = Buffer.from(await file.arrayBuffer());
    const filePath = path.join(uploadDir, file.name || "upload.zip");
    await fs.writeFile(filePath, buffer);

    // Extract if ZIP or tar.gz
    const fileName = file.name?.toLowerCase() || "";
    const isTarGz = fileName.endsWith(".tar.gz") || fileName.endsWith(".tgz");
    const isTar = fileName.endsWith(".tar");
    const is7z = fileName.endsWith(".7z");
    const isRar = fileName.endsWith(".rar");
    const isZipFamily = fileName.endsWith(".zip") || fileName.endsWith(".jar") || fileName.endsWith(".war") || file.type === "application/zip";

    // Extract with shared Zip Slip + symlink guards (CWE-22): entries are
    // validated BEFORE extraction, escaping symlinks purged AFTER it.
    if (isTarGz || isTar) {
      try {
        await extractArchiveSafely(isTar ? "tar" : "targz", filePath, uploadDir);
        await fs.unlink(filePath).catch(() => {});
      } catch (tarError) {
        console.error("tar extraction failed:", tarError);
        if (tarError instanceof UnsafeArchiveError) {
          return NextResponse.json({ error: "Archivo rechazado por seguridad" }, { status: 400 });
        }
      }
    } else if (is7z) {
      try {
        await extractArchiveSafely("7z", filePath, uploadDir);
        await fs.unlink(filePath).catch(() => {});
      } catch (e) {
        console.error("7z extraction failed:", e);
        if (e instanceof UnsafeArchiveError) {
          return NextResponse.json({ error: "Archivo rechazado por seguridad" }, { status: 400 });
        }
      }
    } else if (isRar) {
      try {
        await extractArchiveSafely("rar", filePath, uploadDir);
        await fs.unlink(filePath).catch(() => {});
      } catch (e) {
        console.error("rar extraction failed:", e);
        if (e instanceof UnsafeArchiveError) {
          return NextResponse.json({ error: "Archivo rechazado por seguridad" }, { status: 400 });
        }
      }
    } else if (isZipFamily) {
      try {
        await extractArchiveSafely("zip", filePath, uploadDir);
        await fs.unlink(filePath).catch(() => {});
      } catch (zipError) {
        console.error("ZIP extraction failed:", zipError);
        if (zipError instanceof UnsafeArchiveError) {
          return NextResponse.json({ error: "Archivo rechazado por seguridad" }, { status: 400 });
        }
      }
    }

    // Purge extracted sources from previous versions of this application so a new
    // upload replaces the old one on disk (DB records are preserved).
    await cleanupOldVersionUploads(application.id, version.id).catch((err) =>
      console.error("Old version upload cleanup failed:", err)
    );

    // Parse scan types
    const scanTypes = scanTypesParam.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) as Array<"sast" | "sca" | "dast">;

    // Enqueue scan
    const { jobId } = await enqueueScan({
      applicationId: application.id,
      versionId: version.id,
      companyId,
      scanTypes,
      source: "api",
      metadata: {
        branch,
        triggeredBy: apiKeyRecord.createdById,
      },
    });

    return NextResponse.json({
      scanId: jobId,
      status: "queued",
      applicationId: application.id,
      versionId: version.id,
    }, { status: 201 });
  } catch (error) {
    console.error("Scan upload error:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { Prisma } from "@prisma/client";
import { mkdir, writeFile, readdir, rm } from "fs/promises";
import { join } from "path";
import { cleanupOldVersionUploads } from "@/lib/upload-cleanup";
import {
  extractArchiveSafely,
  type ArchiveKind,
} from "@/lib/upload/safe-extract";

// Large uploads (up to 1GB) are handled natively: App Router route handlers
// stream the request body (no Pages-Router `bodyParser`), and the body-size
// limit is raised via `experimental.proxyClientMaxBodySize` in next.config.ts.

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; versionId: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { id, versionId } = await params;

    // Verify ownership
    const version = await prisma.appVersion.findFirst({
      where: {
        id: versionId,
        applicationId: id,
        application: { companyId: session.user.companyId },
      },
    });

    if (!version) {
      return NextResponse.json({ error: "Versión no encontrada" }, { status: 404 });
    }

    const formData = await request.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json({ error: "Archivo requerido" }, { status: 400 });
    }

    // Validate file
    const maxSize = 1024 * 1024 * 1024; // 1GB
    if (file.size > maxSize) {
      return NextResponse.json(
        { error: "El archivo excede el tamaño máximo de 1GB" },
        { status: 400 }
      );
    }

    const allowedTypes = [
      "application/zip",
      "application/x-zip-compressed",
      "application/x-zip",
      "multipart/x-zip",
      "application/gzip",
      "application/x-gzip",
      "application/x-tar",
      "application/x-compressed-tar",
      "application/java-archive",
      "application/x-7z-compressed",
      "application/x-rar-compressed",
      "application/vnd.rar",
    ];
    const name = file.name.toLowerCase();
    const isZipFamily = allowedTypes.includes(file.type) ||
      name.endsWith(".zip") || name.endsWith(".jar") || name.endsWith(".war");
    const isTarFamily = name.endsWith(".tar.gz") || name.endsWith(".tgz") || name.endsWith(".tar") ||
      ["application/gzip", "application/x-gzip", "application/x-tar", "application/x-compressed-tar"].includes(file.type);
    const is7z = name.endsWith(".7z") || file.type === "application/x-7z-compressed";
    const isRar = name.endsWith(".rar") || ["application/x-rar-compressed", "application/vnd.rar"].includes(file.type);

    if (!isZipFamily && !isTarFamily && !is7z && !isRar) {
      return NextResponse.json(
        { error: "Formatos soportados: .zip, .tar.gz, .tgz, .tar, .jar, .war, .7z, .rar" },
        { status: 400 }
      );
    }

    // Save the file
    const uploadDir = join(process.cwd(), "uploads", versionId);
    await mkdir(uploadDir, { recursive: true });

    // Clean previously extracted files so a re-upload doesn't accumulate
    // stale sources (which would duplicate findings and inflate LOC counts).
    try {
      const existing = await readdir(uploadDir);
      await Promise.all(
        existing.map((entry) => rm(join(uploadDir, entry), { recursive: true, force: true }))
      );
    } catch (cleanErr) {
      console.error("Failed to clean upload dir before extraction:", cleanErr);
    }

    const ext = name.endsWith(".tar.gz") ? ".tar.gz" : name.slice(name.lastIndexOf("."));
    const archivePath = join(uploadDir, `source${ext}`);
    const bytes = await file.arrayBuffer();
    await writeFile(archivePath, Buffer.from(bytes));

    // Extract archive. Zip Slip + symlink guards live in the shared helper
    // (CWE-22): entries are validated BEFORE extraction and escaping
    // symlinks are purged AFTER it.
    try {
      const kind: ArchiveKind = isTarFamily
        ? name.endsWith(".tar")
          ? "tar"
          : "targz"
        : is7z
          ? "7z"
          : isRar
            ? "rar"
            : "zip";
      await extractArchiveSafely(kind, archivePath, uploadDir);
    } catch (err) {
      console.error("Failed to extract archive:", err);
      return NextResponse.json(
        { error: "Error al descomprimir el archivo. Verifica que el formato sea válido." },
        { status: 400 }
      );
    }

    // Count lines of code
    const codeFiles = await countLinesOfCode(uploadDir);

    // Update version with file info
    await prisma.appVersion.update({
      where: { id: versionId },
      data: {
        sourceUrl: archivePath,
        fileSize: BigInt(file.size),
        linesOfCode: codeFiles.totalLines,
      },
    });

    // Purge extracted sources from PREVIOUS versions of this application so a new
    // upload replaces the old one on disk (DB records are preserved). Without this,
    // every new version accumulates hundreds of MB of duplicated extracted code.
    await cleanupOldVersionUploads(id, versionId).catch((err) =>
      console.error("Old version upload cleanup failed:", err)
    );

    await prisma.auditLog.create({
      data: {
        action: "UPLOAD",
        entityType: "AppVersion",
        entityId: versionId,
        newValues: { fileName: file.name, size: file.size } as Prisma.InputJsonValue,
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json({
      success: true,
      fileSize: file.size,
      linesOfCode: codeFiles.totalLines,
      fileCount: codeFiles.fileCount,
    });
  } catch (error) {
    console.error("Upload error:", error);
    const message = error instanceof Error ? error.message : "Error interno";
    return NextResponse.json({ error: `Error interno: ${message}` }, { status: 500 });
  }
}

async function countLinesOfCode(dir: string): Promise<{ totalLines: number; fileCount: number }> {
  const fs = await import("fs/promises");
  const path = await import("path");
  const codeExts = [".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp", ".rs", ".swift", ".kt"];

  let totalLines = 0;
  let fileCount = 0;

  async function walk(d: string) {
    const entries = await fs.readdir(d, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(d, entry.name);
      if (["node_modules",".git","__pycache__",".venv","venv","vendor","target","Pods",".gradle","bower_components","dist","build","out",".next","coverage",".cache","pkg","bin","obj"].includes(entry.name)) continue;
      if (entry.isDirectory()) {
        await walk(full);
      } else if (codeExts.includes(path.extname(entry.name).toLowerCase())) {
        try {
          const content = await fs.readFile(full, "utf-8");
          totalLines += content.split("\n").length;
          fileCount++;
        } catch {
          // skip binary/unreadable files
        }
      }
    }
  }

  await walk(dir);
  return { totalLines, fileCount };
}

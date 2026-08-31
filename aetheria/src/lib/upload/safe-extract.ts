import { execFile } from "child_process";
import { promisify } from "util";
import { promises as fs } from "fs";
import path from "path";

const execFileAsync = promisify(execFile);
const LISTING_OPTS = { maxBuffer: 64 * 1024 * 1024 };

export class UnsafeArchiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeArchiveError";
  }
}

export type ArchiveKind = "tar" | "targz" | "7z" | "rar" | "zip";

/**
 * Zip Slip guard (CWE-22): an authenticated upload must never write outside
 * the destination directory. adm-zip / tar / 7z / unrar do NOT sanitize entry
 * names, so entries are listed and validated BEFORE extraction:
 *   - rejects `..` path segments, absolute paths and drive-letter paths
 *   - rejects symlink / hardlink entries (an archive can plant a symlink to
 *     /app and then write a later entry THROUGH it, escaping the directory
 *     even when every entry name looks clean)
 * After extraction, any symlink that resolves outside the destination is
 * removed as defense-in-depth.
 */
export function isUnsafeEntryName(p: string): boolean {
  const n = p.replace(/\\/g, "/");
  return (
    n.split("/").includes("..") ||
    n.startsWith("/") ||
    /^[a-zA-Z]:\//.test(n)
  );
}

async function validateTar(archivePath: string, gzip: boolean): Promise<void> {
  const flag = gzip ? "-tzvf" : "-tvf";
  const { stdout } = await execFileAsync("tar", [flag, archivePath], LISTING_OPTS);
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    // Verbose listing: first char is the entry type (l = symlink, h = hardlink).
    const type = line[0];
    if (type === "l" || type === "h") {
      throw new UnsafeArchiveError(`Unsafe link entry rejected: ${line.trim()}`);
    }
    // Columns: mode links owner group size date time name[ -> target]
    const rest = line.split(/\s+/).slice(5).join(" ");
    const name = rest.split(" -> ")[0];
    if (name && isUnsafeEntryName(name)) {
      throw new UnsafeArchiveError(`Unsafe archive entry rejected: ${name}`);
    }
  }
}

async function validate7z(archivePath: string): Promise<string[]> {
  const { stdout } = await execFileAsync("7z", ["l", "-slt", archivePath], LISTING_OPTS);
  const names: string[] = [];
  for (const line of stdout.split("\n")) {
    if (line.startsWith("Path = ")) {
      names.push(line.slice("Path = ".length).trim());
    } else if (line.startsWith("Attributes = ")) {
      // p7zip marks unix symlinks with a leading 'l' in the mode string.
      const attrs = line.slice("Attributes = ".length).trim();
      if (attrs.startsWith("l")) {
        throw new UnsafeArchiveError("Unsafe symlink entry rejected in 7z archive");
      }
    }
  }
  for (const name of names) {
    if (name && isUnsafeEntryName(name)) {
      throw new UnsafeArchiveError(`Unsafe archive entry rejected: ${name}`);
    }
  }
  return names;
}

async function validateRar(archivePath: string): Promise<string[]> {
  // p7zip's `7z` reads RAR archives (including RAR5); the production image
  // ships p7zip-full, not the non-free `unrar`. The -slt listing gives the
  // same Path/Attributes fields used by the 7z validator.
  return validate7z(archivePath);
}

async function validateZip(archivePath: string): Promise<InstanceType<typeof import("adm-zip")>> {
  const AdmZip = (await import("adm-zip")).default;
  const zip = new AdmZip(archivePath);
  for (const entry of zip.getEntries()) {
    if (isUnsafeEntryName(entry.entryName)) {
      throw new UnsafeArchiveError(`Unsafe archive entry rejected: ${entry.entryName}`);
    }
    // Unix mode bits live in the high 16 bits of external attributes.
    // 0o120000 (S_IFLNK) marks a symlink entry.
    if (((entry.attr >>> 16) & 0o170000) === 0o120000) {
      throw new UnsafeArchiveError(`Unsafe symlink entry rejected: ${entry.entryName}`);
    }
  }
  return zip;
}

async function purgeEscapingSymlinks(dir: string, root: string): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) {
      const real = await fs.realpath(full).catch(() => null);
      if (!real || (real !== root && !real.startsWith(root + path.sep))) {
        await fs.unlink(full).catch(() => {});
      }
    } else if (e.isDirectory()) {
      await purgeEscapingSymlinks(full, root);
    }
  }
}

/**
 * Validates and extracts an uploaded archive into destDir.
 * Throws UnsafeArchiveError on malicious entries (caller should map to 400).
 */
export async function extractArchiveSafely(
  kind: ArchiveKind,
  archivePath: string,
  destDir: string
): Promise<void> {
  const root = path.resolve(destDir);

  switch (kind) {
    case "tar":
      await validateTar(archivePath, false);
      await execFileAsync("tar", ["-xf", archivePath, "-C", destDir]);
      break;
    case "targz":
      await validateTar(archivePath, true);
      await execFileAsync("tar", ["-xzf", archivePath, "-C", destDir]);
      break;
    case "7z":
      await validate7z(archivePath);
      await execFileAsync("7z", ["x", archivePath, `-o${destDir}`, "-y"]);
      break;
    case "rar":
      await validateRar(archivePath);
      await execFileAsync("7z", ["x", archivePath, `-o${destDir}`, "-y"]);
      break;
    case "zip": {
      const zip = await validateZip(archivePath);
      zip.extractAllTo(destDir, true);
      break;
    }
  }

  await purgeEscapingSymlinks(root, root);
}

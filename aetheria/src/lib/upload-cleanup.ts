import { rm } from "fs/promises";
import { join } from "path";
import { prisma } from "@/lib/db";

/**
 * Remove the extracted source artifacts of every OTHER version belonging to the
 * same application, keeping only `keepVersionId` on disk.
 *
 * Rationale: each upload extracts the archive into `uploads/<versionId>`. When a
 * new version of an application is uploaded, the previous versions' extracted
 * sources are stale and only waste disk (hundreds of MB of duplicated code).
 * This purges them so "uploading a new file replaces the previous one".
 *
 * Only the on-disk artifacts are deleted — the DB records (AppVersion, Analysis,
 * Vulnerability) are preserved, so historical scan results remain visible.
 *
 * @returns number of version directories removed.
 */
export async function cleanupOldVersionUploads(
  applicationId: string,
  keepVersionId: string
): Promise<number> {
  const otherVersions = await prisma.appVersion.findMany({
    where: { applicationId, id: { not: keepVersionId } },
    select: { id: true },
  });

  let removed = 0;
  for (const v of otherVersions) {
    try {
      await rm(join(process.cwd(), "uploads", v.id), { recursive: true, force: true });
      removed++;
    } catch (err) {
      console.error(`Failed to cleanup upload dir for version ${v.id}:`, err);
    }
  }

  if (removed > 0) {
    console.log(`[upload-cleanup] Removed ${removed} stale version upload(s) for app ${applicationId}`);
  }
  return removed;
}

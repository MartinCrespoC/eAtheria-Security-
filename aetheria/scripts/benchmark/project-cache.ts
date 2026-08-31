/**
 * OpenSSF CVE Benchmark — full-project fetch + cache.
 *
 * The official benchmark runs tools over the WHOLE project tree at the
 * vulnerable and patched commits (not just the affected file). This module
 * closes that approximation gap: it downloads the GitHub tarball for
 * `repo@commit` (codeload), extracts it under
 * `vendor/fp/cve-benchmark/project-cache/<CVE>/<stage>/`, and materializes a
 * `Map<relativePath, content>` of scannable files for the analysis engines.
 *
 * Non-fatal by design: any fetch/extract failure returns null and the caller
 * falls back to single-file analysis.
 */
import * as fs from "fs";
import * as path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { CVE_BENCHMARK_DIR } from "./setup/cve-benchmark";

const execFileAsync = promisify(execFile);

/** Local cache for full project trees (one subdir per CVE + stage). */
export const CVE_PROJECT_CACHE = path.join(CVE_BENCHMARK_DIR, "project-cache");

const SCANNABLE_EXTS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".json"]);
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", "coverage", ".nyc_output",
  ".next", ".cache", "vendor", "third_party", "fixtures",
]);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_PROJECT_FILES = 800;
const MAX_PROJECT_BYTES = 40 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 120_000;

/** Extract the owner/repo pair from a GitHub URL, or null. */
export function repoSlugFromUrl(repoUrl: string): string | null {
  const m = /github\.com\/([^/]+\/[^/]+?)(?:\.git)?\/?$/.exec(repoUrl);
  return m ? m[1] : null;
}

/**
 * Ensure the project tree for `repo@commit` is extracted in the cache and
 * return its root directory (the single top-level folder of the tarball), or
 * null on any failure.
 */
export async function ensureProjectTree(
  repoUrl: string,
  commit: string,
  cveId: string,
  stage: "pre" | "post",
): Promise<string | null> {
  const slug = repoSlugFromUrl(repoUrl);
  if (!slug) return null;
  const destDir = path.join(CVE_PROJECT_CACHE, cveId, stage);
  const marker = path.join(destDir, ".extracted");
  if (fs.existsSync(marker)) {
    const entries = fs.readdirSync(destDir).filter((e) => !e.startsWith("."));
    if (entries.length === 1) return path.join(destDir, entries[0]);
    return destDir;
  }

  const tarballUrl = `https://codeload.github.com/${slug}/tar.gz/${commit}`;
  const tgzPath = path.join(destDir, "tree.tar.gz");
  try {
    fs.rmSync(destDir, { recursive: true, force: true });
    fs.mkdirSync(destDir, { recursive: true });
    const res = await fetch(tarballUrl, { redirect: "follow" });
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_PROJECT_BYTES * 4) return null; // absurdly large repo
    fs.writeFileSync(tgzPath, buf);
    await execFileAsync("tar", ["-xzf", tgzPath, "-C", destDir], {
      timeout: FETCH_TIMEOUT_MS,
    });
    fs.unlinkSync(tgzPath);
    fs.writeFileSync(marker, commit);
    const entries = fs.readdirSync(destDir).filter((e) => !e.startsWith("."));
    if (entries.length === 1) return path.join(destDir, entries[0]);
    return destDir;
  } catch {
    return null;
  }
}

/**
 * Materialize the scannable files of an extracted project tree as
 * `Map<relativePosixPath, content>`. Bounded by per-file and per-project caps.
 */
export function collectProjectFiles(rootDir: string): Map<string, string> | null {
  if (!fs.existsSync(rootDir)) return null;
  const files = new Map<string, string>();
  let totalBytes = 0;

  const walk = (dir: string, rel: string): boolean => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return true;
    }
    for (const e of entries) {
      if (files.size >= MAX_PROJECT_FILES || totalBytes >= MAX_PROJECT_BYTES) return false;
      const relPath = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith(".")) continue;
        if (!walk(path.join(dir, e.name), relPath)) return false;
      } else if (e.isFile()) {
        if (!SCANNABLE_EXTS.has(path.extname(e.name).toLowerCase())) continue;
        if (e.name.endsWith(".min.js") || e.name.endsWith(".min.css")) continue;
        const abs = path.join(dir, e.name);
        try {
          const stat = fs.statSync(abs);
          if (stat.size > MAX_FILE_BYTES) continue;
          const content = fs.readFileSync(abs, "utf8");
          files.set(relPath, content);
          totalBytes += stat.size;
        } catch {
          /* unreadable file — skip */
        }
      }
    }
    return true;
  };

  walk(rootDir, "");
  return files.size > 0 ? files : null;
}

/**
 * Fetch (cached) the full project file set for one side of a CVE case.
 * Returns null on any failure — callers fall back to single-file analysis.
 */
export async function fetchProjectFiles(
  repoUrl: string,
  commit: string,
  cveId: string,
  stage: "pre" | "post",
): Promise<Map<string, string> | null> {
  const root = await ensureProjectTree(repoUrl, commit, cveId, stage);
  if (!root) return null;
  return collectProjectFiles(root);
}

import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { decrypt } from "@/lib/crypto";

export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ connectionId: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const { connectionId } = await params;

    const connection = await prisma.githubConnection.findFirst({
      where: { id: connectionId, companyId: session.user.companyId },
    });

    if (!connection) {
      return NextResponse.json({ error: "Conexión no encontrada" }, { status: 404 });
    }

    // Decrypt token
    const token = decrypt(connection.accessToken);

    // Fetch repos from GitHub API
    const repos: GitHubRepo[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const res = await fetch(`https://api.github.com/user/repos?per_page=100&page=${page}&sort=updated`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });

      if (!res.ok) {
        return NextResponse.json(
          { error: "Error al conectar con GitHub" },
          { status: 502 }
        );
      }

      const data: GitHubRepo[] = await res.json();
      repos.push(...data);

      if (data.length < 100) hasMore = false;
      else page++;

      // Safety limit
      if (page > 10) hasMore = false;
    }

    // Upsert repos
    let syncedCount = 0;
    for (const repo of repos) {
      await prisma.githubRepository.upsert({
        where: {
          connectionId_repoId: {
            connectionId,
            repoId: String(repo.id),
          },
        },
        update: {
          name: repo.name,
          fullName: repo.full_name,
          description: repo.description || null,
          htmlUrl: repo.html_url,
          cloneUrl: repo.clone_url,
          defaultBranch: repo.default_branch || "main",
          language: repo.language || null,
          isPrivate: repo.private,
        },
        create: {
          repoId: String(repo.id),
          name: repo.name,
          fullName: repo.full_name,
          description: repo.description || null,
          htmlUrl: repo.html_url,
          cloneUrl: repo.clone_url,
          defaultBranch: repo.default_branch || "main",
          language: repo.language || null,
          isPrivate: repo.private,
          connectionId,
        },
      });
      syncedCount++;
    }

    // Update connection sync timestamp
    await prisma.githubConnection.update({
      where: { id: connectionId },
      data: { lastSyncAt: new Date() },
    });

    return NextResponse.json({
      success: true,
      synced: syncedCount,
      total: repos.length,
    });
  } catch (error) {
    console.error("GitHub sync error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  description: string | null;
  html_url: string;
  clone_url: string;
  default_branch: string;
  language: string | null;
  private: boolean;
}

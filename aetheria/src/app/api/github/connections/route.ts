import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { encrypt } from "@/lib/crypto";

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const connections = await prisma.githubConnection.findMany({
      where: { companyId: session.user.companyId },
      select: {
        id: true,
        name: true,
        username: true,
        avatarUrl: true,
        isActive: true,
        lastSyncAt: true,
        createdAt: true,
        _count: { select: { repositories: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(connections);
  } catch (error) {
    console.error("Error fetching GitHub connections:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const body = await request.json();
    const { name, accessToken, username } = body;

    if (!name || !accessToken) {
      return NextResponse.json(
        { error: "Nombre y token son obligatorios" },
        { status: 400 }
      );
    }

    // Validate token with GitHub API
    const ghRes = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!ghRes.ok) {
      return NextResponse.json(
        { error: "Token de GitHub inválido" },
        { status: 400 }
      );
    }

    const ghUser = await ghRes.json();

    // Encrypt the token before storing
    const encryptedToken = encrypt(accessToken);

    const connection = await prisma.githubConnection.create({
      data: {
        name: name.trim(),
        accessToken: encryptedToken,
        username: username?.trim() || ghUser.login,
        avatarUrl: ghUser.avatar_url,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json(
      { id: connection.id, name: connection.name },
      { status: 201 }
    );
  } catch (error) {
    console.error("Error creating GitHub connection:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

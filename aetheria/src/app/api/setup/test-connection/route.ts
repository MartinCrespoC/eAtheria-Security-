import { NextRequest, NextResponse } from "next/server";
import {
  type DatabaseProvider,
  validateConnectionUrl,
  buildConnectionUrl,
  testConnection,
  resolveReachableUrl,
} from "@/lib/infrastructure/db-adapter";
import net from "net";
import { existsSync, mkdirSync } from "fs";
import { dirname } from "path";
import { getPrisma } from "@/lib/infrastructure/db-adapter";

export const dynamic = "force-dynamic";

/**
 * Check if setup is already complete.
 */
async function isSetupComplete(): Promise<boolean> {
  try {
    const client = getPrisma();
    const config = await client.systemConfig.findUnique({
      where: { key: "setup_complete" },
    });
    return config?.value === true;
  } catch {
    return false;
  }
}

/**
 * Parse a connection URL to extract host and port.
 */
function parseHostPort(url: string): { host: string; port: number } | null {
  try {
    const match = url.match(/^(?:\w+:\/\/)?(?:[^@]+@)?([^:/]+)(?::(\d+))?/);
    if (match) {
      return {
        host: match[1],
        port: match[2] ? parseInt(match[2], 10) : 5432,
      };
    }
  } catch {
    // ignore
  }
  return null;
}

/**
 * Test TCP connectivity to a host:port.
 */
function testTcpConnection(host: string, port: number): Promise<{ success: boolean; error?: string }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 5000 });
    let settled = false;

    const done = (success: boolean, error?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success, error });
    };

    socket.on("connect", () => done(true));
    socket.on("error", (err) => done(false, err.message));
    socket.on("timeout", () => done(false, "Connection timed out"));
  });
}

/**
 * Test SQLite file path accessibility.
 */
function testSqlitePath(filePath: string): { success: boolean; error?: string } {
  // Remove file: prefix if present
  const path = filePath.replace(/^(file:|sqlite:)/, "");

  try {
    const dir = dirname(path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: `Cannot create database file at ${path}: ${error instanceof Error ? error.message : "Unknown error"}`,
    };
  }
}

/**
 * POST /api/setup/test-connection
 *
 * Body: { provider, connectionUrl } or { provider, host, port, database, user, password }
 *
 * Tests a database connection without persisting anything.
 * Returns: { success: boolean, error?: string, latencyMs?: number }
 */
export async function POST(request: NextRequest) {
  // Security: block if setup is already complete
  if (await isSetupComplete()) {
    return NextResponse.json(
      { success: false, error: "Setup is already complete" },
      { status: 403 }
    );
  }

  try {
    const body = await request.json();
    const provider = body.provider as DatabaseProvider;

    if (!provider || !["postgresql", "sqlite", "mysql"].includes(provider)) {
      return NextResponse.json(
        { success: false, error: "Invalid or missing provider" },
        { status: 400 }
      );
    }

    // Build connection URL from either format
    let connectionUrl: string;
    if (body.connectionUrl) {
      connectionUrl = body.connectionUrl;
    } else if (body.host) {
      connectionUrl = buildConnectionUrl({
        provider,
        host: body.host,
        port: body.port,
        database: body.database,
        user: body.user,
        password: body.password,
        filePath: body.filePath,
      });
    } else {
      return NextResponse.json(
        { success: false, error: "Must provide connectionUrl or host/database fields" },
        { status: 400 }
      );
    }

    // Validate URL format
    const validation = validateConnectionUrl(connectionUrl, provider);
    if (!validation.valid) {
      return NextResponse.json({
        success: false,
        error: validation.error,
      });
    }

    const startTime = Date.now();

    // SQLite: test file path
    if (provider === "sqlite") {
      const result = testSqlitePath(connectionUrl);
      return NextResponse.json({
        ...result,
        latencyMs: Date.now() - startTime,
      });
    }

    // PostgreSQL / MySQL: resolve a reachable host (Docker-aware).
    // "localhost" inside a container means the app container itself — when
    // it fails, probe common alternatives and use the one that answers.
    const resolved = await resolveReachableUrl(connectionUrl, provider);
    if (!resolved) {
      const hostPort = parseHostPort(connectionUrl);
      return NextResponse.json({
        success: false,
        error: `Cannot reach ${hostPort?.host ?? "the database host"}:${hostPort?.port ?? ""}. Ensure the database server is running and reachable from this container (tip: use the container/service name, e.g. aetheria-db — not localhost).`,
        latencyMs: Date.now() - startTime,
      });
    }
    const effectiveUrl = resolved.url;
    const hostNote =
      resolved.resolvedHost !== resolved.originalHost
        ? `Host "${resolved.originalHost}" no era alcanzable; usando "${resolved.resolvedHost}".`
        : undefined;

    // For PostgreSQL: also try a full Prisma connection test
    // (MySQL can't be tested with a PG-generated Prisma client, TCP check is sufficient)
    const currentProvider = process.env.DATABASE_PROVIDER || "postgresql";
    if (provider === currentProvider) {
      const result = await testConnection(effectiveUrl, provider);
      return NextResponse.json({ ...result, resolvedUrl: effectiveUrl, note: hostNote });
    }

    // Provider mismatch — TCP check passed, that's sufficient
    return NextResponse.json({
      success: true,
      resolvedUrl: effectiveUrl,
      note: hostNote,
      latencyMs: Date.now() - startTime,
    });
  } catch (error) {
    console.error("[SETUP] Test connection error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

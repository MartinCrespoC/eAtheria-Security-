/**
 * Database Adapter - Multi-DB Connection Abstraction
 *
 * Provides:
 * - Provider validation (postgresql | sqlite | mysql)
 * - Connection URL validation per provider
 * - Singleton PrismaClient export
 * - healthCheck() for runtime monitoring
 * - testConnection() for the web installer
 */

import { PrismaClient } from "@prisma/client";
import { existsSync } from "fs";
import net from "net";

export type DatabaseProvider = "postgresql" | "sqlite" | "mysql";

export interface ConnectionTestResult {
  success: boolean;
  error?: string;
  latencyMs?: number;
}

/**
 * Get the current PrismaClient singleton from the global scope.
 * Used by setup API routes to always access the latest client
 * (important after resetPrismaClient() is called during DB initialization).
 */
export function getPrisma(): PrismaClient {
  const globalForPrisma = globalThis as unknown as {
    prisma: PrismaClient | undefined;
  };
  if (!globalForPrisma.prisma) {
    globalForPrisma.prisma = new PrismaClient({
      log:
        process.env.NODE_ENV === "development"
          ? ["query", "error", "warn"]
          : ["error"],
    });
  }
  return globalForPrisma.prisma;
}

/**
 * Get the configured database provider from environment.
 * Defaults to "postgresql".
 */
export function getDatabaseProvider(): DatabaseProvider {
  const provider = process.env.DATABASE_PROVIDER?.toLowerCase() as DatabaseProvider;
  if (provider && ["postgresql", "sqlite", "mysql"].includes(provider)) {
    return provider;
  }
  return "postgresql";
}

/**
 * Validate that a connection URL matches the expected provider format.
 */
export function validateConnectionUrl(
  url: string,
  provider: DatabaseProvider
): { valid: boolean; error?: string } {
  if (!url || typeof url !== "string") {
    return { valid: false, error: "Connection URL is required" };
  }

  switch (provider) {
    case "postgresql":
      if (!url.startsWith("postgresql://") && !url.startsWith("postgres://")) {
        return {
          valid: false,
          error: "PostgreSQL URL must start with postgresql:// or postgres://",
        };
      }
      break;

    case "mysql":
      if (!url.startsWith("mysql://")) {
        return {
          valid: false,
          error: "MySQL URL must start with mysql://",
        };
      }
      break;

    case "sqlite":
      // SQLite uses file: protocol or direct file paths
      if (
        !url.startsWith("file:") &&
        !url.startsWith("sqlite:") &&
        !url.endsWith(".db") &&
        !url.endsWith(".sqlite") &&
        !url.endsWith(".sqlite3")
      ) {
        // Allow raw paths too — SQLite accepts any file path
        if (!url.includes("/")) {
          return {
            valid: false,
            error:
              "SQLite URL must be a file path (e.g., file:./prisma/dev.db or ./prisma/dev.db)",
          };
        }
      }
      break;

    default:
      return { valid: false, error: `Unsupported provider: ${provider}` };
  }

  return { valid: true };
}

/**
 * Build a connection URL from individual components.
 */
export function buildConnectionUrl(params: {
  provider: DatabaseProvider;
  host?: string;
  port?: string | number;
  database?: string;
  user?: string;
  password?: string;
  filePath?: string;
}): string {
  const { provider } = params;

  switch (provider) {
    case "postgresql": {
      const host = params.host || "localhost";
      const port = params.port || 5432;
      const db = params.database || "aetheria";
      const creds = params.user
        ? `${encodeURIComponent(params.user)}${params.password ? ":" + encodeURIComponent(params.password) : ""}@`
        : "";
      return `postgresql://${creds}${host}:${port}/${db}`;
    }

    case "mysql": {
      const host = params.host || "localhost";
      const port = params.port || 3306;
      const db = params.database || "aetheria";
      const creds = params.user
        ? `${encodeURIComponent(params.user)}${params.password ? ":" + encodeURIComponent(params.password) : ""}@`
        : "";
      return `mysql://${creds}${host}:${port}/${db}`;
    }

    case "sqlite": {
      const path = params.filePath || "./prisma/dev.db";
      if (path.startsWith("file:") || path.startsWith("sqlite:")) return path;
      return `file:${path}`;
    }

    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

/**
 * TCP-level connectivity check to the host:port in a connection URL.
 * Used when the in-process Prisma client was generated for a DIFFERENT
 * provider: such a client rejects foreign URL protocols before even
 * attempting a connection, so a real handshake isn't possible in-process.
 */
export function testTcpConnectivity(
  connectionUrl: string,
  provider: DatabaseProvider
): Promise<ConnectionTestResult> {
  const defaultPorts: Record<DatabaseProvider, number> = {
    postgresql: 5432,
    mysql: 3306,
    sqlite: 0,
  };

  const startTime = Date.now();

  let host: string;
  let port: number;
  try {
    const url = new URL(connectionUrl);
    host = url.hostname;
    port = url.port ? parseInt(url.port, 10) : defaultPorts[provider];
  } catch {
    return Promise.resolve({ success: false, error: "Invalid connection URL" });
  }

  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 5000 });
    let settled = false;
    const done = (success: boolean, error?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        success,
        error: error
          ? `Cannot reach ${host}:${port} — ${error}. Ensure the database server is running.`
          : undefined,
        latencyMs: Date.now() - startTime,
      });
    };
    socket.on("connect", () => done(true));
    socket.on("error", (err) => done(false, err.message));
    socket.on("timeout", () => done(false, "connection timed out"));
  });
}

/**
 * Resolve a connection URL whose host is unreachable — the classic case is
 * "localhost" typed into the installer while the app runs inside Docker
 * (localhost = the app container, not the DB host). Probes a list of
 * plausible alternatives (docker host gateway, common container names)
 * with the same port/credentials/database and returns the first URL that
 * answers TCP. Returns null when nothing answers.
 */
export async function resolveReachableUrl(
  connectionUrl: string,
  provider: DatabaseProvider
): Promise<{ url: string; resolvedHost: string; originalHost: string } | null> {
  if (provider === "sqlite") return { url: connectionUrl, resolvedHost: "", originalHost: "" };

  let parsed: URL;
  try {
    parsed = new URL(connectionUrl);
  } catch {
    return null;
  }

  const defaultPort = provider === "mysql" ? 3306 : 5432;
  const port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;
  const originalHost = parsed.hostname;

  const tryTcp = (host: string) =>
    new Promise<boolean>((resolve) => {
      const socket = net.createConnection({ host, port, timeout: 2500 });
      let settled = false;
      const done = (ok: boolean) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(ok);
      };
      socket.on("connect", () => done(true));
      socket.on("error", () => done(false));
      socket.on("timeout", () => done(false));
    });

  // 1. The URL as given
  if (await tryTcp(originalHost)) {
    return { url: connectionUrl, resolvedHost: originalHost, originalHost };
  }

  // 2. Alternatives, most likely first
  const candidates = [
    "host.docker.internal",
    "aetheria-db",
    "postgres",
    "postgresql",
    "db",
    "shared-postgres",
  ].filter((h) => h !== originalHost);

  for (const host of candidates) {
    if (await tryTcp(host)) {
      parsed.hostname = host;
      return { url: parsed.toString(), resolvedHost: host, originalHost };
    }
  }

  return null;
}

/**
 * Test a database connection WITHOUT persisting the PrismaClient.
 * Used by the web installer's "Test Connection" button.
 *
 * This creates a temporary PrismaClient, runs a simple query, then disconnects.
 */
export async function testConnection(
  connectionUrl: string,
  provider: DatabaseProvider
): Promise<ConnectionTestResult> {
  const validation = validateConnectionUrl(connectionUrl, provider);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  const startTime = Date.now();

  // The in-process client was generated for the build/current provider.
  // A different provider's URL would fail protocol validation in-process,
  // so fall back to a TCP check — the regenerated client's db push does
  // the real credential validation afterwards.
  const buildProvider = (
    process.env.DATABASE_PROVIDER || "postgresql"
  ).toLowerCase() as DatabaseProvider;
  if (provider !== buildProvider) {
    if (provider === "sqlite") {
      // No server to probe; the file is created/validated by db push.
      return { success: true, latencyMs: Date.now() - startTime };
    }
    return testTcpConnectivity(connectionUrl, provider);
  }

  try {
    // Create a temporary client with the provided URL
    const tempClient = new PrismaClient({
      datasources: {
        db: { url: connectionUrl },
      },
      log: ["error"],
    });

    // Run a simple health query
    await tempClient.$connect();

    // Execute a simple ping query
    await tempClient.$queryRaw`SELECT 1 as ok`;

    await tempClient.$disconnect();

    const latencyMs = Date.now() - startTime;
    return { success: true, latencyMs };
  } catch (error) {
    const latencyMs = Date.now() - startTime;
    const message =
      error instanceof Error ? error.message : "Unknown connection error";

    // Provide user-friendly error messages
    let friendlyError = message;
    if (message.includes("ECONNREFUSED")) {
      friendlyError = `Connection refused — ensure the database server is running and accessible at the specified host/port.`;
    } else if (message.includes("ENOTFOUND")) {
      friendlyError = `Host not found — check the hostname in your connection string.`;
    } else if (message.includes("authentication failed") || message.includes("password")) {
      friendlyError = `Authentication failed — check your username and password.`;
    } else if (message.includes("database") && message.includes("does not exist")) {
      friendlyError = `Database does not exist — create it first or check the database name.`;
    } else if (message.includes("timeout")) {
      friendlyError = `Connection timed out — the database server did not respond in time.`;
    }

    return {
      success: false,
      error: friendlyError,
      latencyMs,
    };
  }
}

/**
 * Health check for the active database connection.
 * Used by monitoring endpoints and startup checks.
 */
export async function healthCheck(): Promise<ConnectionTestResult> {
  const startTime = Date.now();

  try {
    const client = getPrisma();
    await client.$queryRaw`SELECT 1 as ok`;
    return { success: true, latencyMs: Date.now() - startTime };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Health check failed";
    return {
      success: false,
      error: message,
      latencyMs: Date.now() - startTime,
    };
  }
}

/**
 * Check if the database has been initialized (tables exist).
 * Used by the installer to determine if migrations need to run.
 */
export async function isDatabaseInitialized(): Promise<boolean> {
  try {
    const client = getPrisma();
    await client.systemConfig.count();
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if the target database exists on the server.
 * Used before migrations to proactively detect missing databases.
 */
export async function checkDatabaseExists(
  connectionUrl: string,
  provider: DatabaseProvider
): Promise<{ exists: boolean; error?: string }> {
  try {
    if (provider === "sqlite") {
      // For SQLite, extract file path from URL (file:./prisma/dev.db)
      const filePath = connectionUrl.replace(/^file:/, "");
      return { exists: existsSync(filePath) };
    }

    if (provider === "postgresql") {
      // Connect to the default 'postgres' database and check pg_database
      const url = new URL(connectionUrl);
      const dbName = url.pathname.replace(/^\//, "");
      url.pathname = "/postgres";

      const tempClient = new PrismaClient({
        datasources: { db: { url: url.toString() } },
        log: ["error"],
      });

      const result = await tempClient.$queryRawUnsafe<{ count: bigint }[]>(
        `SELECT COUNT(*) as count FROM pg_database WHERE datname = $1`,
        dbName
      );
      await tempClient.$disconnect();

      return { exists: Number(result[0]?.count || 0) > 0 };
    }

    if (provider === "mysql") {
      // Connect without database and check information_schema
      const url = new URL(connectionUrl);
      const dbName = url.pathname.replace(/^\//, "");
      url.pathname = "/";

      const tempClient = new PrismaClient({
        datasources: { db: { url: url.toString() } },
        log: ["error"],
      });

      const result = await tempClient.$queryRawUnsafe<{ count: bigint }[]>(
        `SELECT COUNT(*) as count FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`,
        dbName
      );
      await tempClient.$disconnect();

      return { exists: Number(result[0]?.count || 0) > 0 };
    }

    return { exists: false, error: `Proveedor no soportado: ${provider}` };
  } catch (error) {
    return {
      exists: false,
      error: error instanceof Error ? error.message : "Error al verificar existencia de la base de datos",
    };
  }
}

/**
 * Attempt to create the database if it doesn't exist.
 * Only works for PostgreSQL and MySQL.
 */
export async function createDatabase(
  connectionUrl: string,
  provider: DatabaseProvider
): Promise<{ success: boolean; error?: string }> {
  try {
    if (provider === "sqlite") {
      // SQLite creates the file automatically on first connection
      return { success: true };
    }

    const url = new URL(connectionUrl);
    const dbName = url.pathname.replace(/^\//, "");

    if (provider === "postgresql") {
      url.pathname = "/postgres";
      const tempClient = new PrismaClient({
        datasources: { db: { url: url.toString() } },
        log: ["error"],
      });
      // Use double-quotes for identifier safety
      await tempClient.$executeRawUnsafe(`CREATE DATABASE "${dbName}"`);
      await tempClient.$disconnect();
      return { success: true };
    }

    if (provider === "mysql") {
      url.pathname = "/";
      const tempClient = new PrismaClient({
        datasources: { db: { url: url.toString() } },
        log: ["error"],
      });
      await tempClient.$executeRawUnsafe(`CREATE DATABASE \`${dbName}\``);
      await tempClient.$disconnect();
      return { success: true };
    }

    return { success: false, error: `Proveedor no soportado: ${provider}` };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Error al crear la base de datos",
    };
  }
}

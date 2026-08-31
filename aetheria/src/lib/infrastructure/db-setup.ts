/**
 * Database Setup Script
 *
 * Handles first-run database configuration:
 * - updateSchemaProvider(provider): modifies prisma/schema.prisma datasource block
 * - runMigrations(): executes prisma migrate deploy
 * - generateClient(): executes prisma generate
 * - seedDatabase(): executes prisma seed
 * - validateConnection(url, provider): tests connection without persisting
 * - updateEnvFile(key, value): updates .env file with new config
 *
 * Can be run standalone: `npx tsx src/lib/infrastructure/db-setup.ts`
 * Or imported by API routes for the web installer.
 */

import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { execSync } from "child_process";
import {
  type DatabaseProvider,
  validateConnectionUrl,
  testConnection,
  isDatabaseInitialized,
  checkDatabaseExists,
  createDatabase,
} from "./db-adapter";

const SCHEMA_PATH = join(process.cwd(), "prisma", "schema.prisma");
const ENV_PATH = join(process.cwd(), ".env");

/**
 * Update the provider in prisma/schema.prisma datasource block.
 * Reads the file, replaces the provider line, and writes it back.
 */
export async function updateSchemaProvider(
  provider: DatabaseProvider
): Promise<void> {
  const schemaContent = await readFile(SCHEMA_PATH, "utf-8");

  // Match: provider = "postgresql" (or "sqlite" or "mysql")
  const providerRegex = /(datasource\s+db\s*\{[\s\S]*?provider\s*=\s*)"[^"]*"/;

  if (!providerRegex.test(schemaContent)) {
    throw new Error("Could not find provider in datasource block of schema.prisma");
  }

  const updated = schemaContent.replace(
    providerRegex,
    `$1"${provider}"`
  );

  await writeFile(SCHEMA_PATH, updated, "utf-8");
  console.log(`[DB-SETUP] Schema provider updated to: ${provider}`);
}

/**
 * Run `prisma generate` to regenerate the client with the current schema.
 */
export function generateClient(): void {
  console.log("[DB-SETUP] Running prisma generate...");
  execSync("npx prisma generate", {
    stdio: "inherit",
    cwd: process.cwd(),
  });
  console.log("[DB-SETUP] Prisma client generated.");
}

/**
 * Run `prisma migrate deploy` to apply all pending migrations.
 */
export function runMigrations(): void {
  console.log("[DB-SETUP] Running prisma migrate deploy...");
  execSync("npx prisma migrate deploy", {
    stdio: "inherit",
    cwd: process.cwd(),
  });
  console.log("[DB-SETUP] Migrations applied.");
}

/**
 * Run `prisma db push` as fallback when no migrations exist (e.g., SQLite).
 */
export function pushSchema(): void {
  console.log("[DB-SETUP] Running prisma db push...");
  execSync("npx prisma db push", {
    stdio: "inherit",
    cwd: process.cwd(),
  });
  console.log("[DB-SETUP] Schema pushed to database.");
}

/**
 * Run the seed script to populate initial data.
 */
export function seedDatabase(): void {
  console.log("[DB-SETUP] Running database seed...");
  execSync("npx tsx prisma/seed.ts", {
    stdio: "inherit",
    cwd: process.cwd(),
  });
  console.log("[DB-SETUP] Database seeded.");
}

/**
 * Validate a connection URL without persisting anything.
 * Delegates to db-adapter.testConnection.
 */
export async function validateConnection(
  connectionUrl: string,
  provider: DatabaseProvider
) {
  const validation = validateConnectionUrl(connectionUrl, provider);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }

  return testConnection(connectionUrl, provider);
}

/**
 * Update or add a key-value pair in the .env file.
 * Creates the file if it doesn't exist.
 */
export async function updateEnvFile(key: string, value: string): Promise<void> {
  let envContent = "";

  if (existsSync(ENV_PATH)) {
    envContent = await readFile(ENV_PATH, "utf-8");
  }

  // Escape special characters in value for shell
  const escapedValue = value.replace(/"/g, '\\"');

  // Check if the key already exists
  const keyRegex = new RegExp(`^${key}=.*$`, "m");

  if (keyRegex.test(envContent)) {
    // Update existing key
    envContent = envContent.replace(keyRegex, `${key}="${escapedValue}"`);
  } else {
    // Add new key at the end
    const prefix = envContent && !envContent.endsWith("\n") ? "\n" : "";
    envContent += `${prefix}${key}="${escapedValue}"\n`;
  }

  await writeFile(ENV_PATH, envContent, "utf-8");
  console.log(`[DB-SETUP] .env updated: ${key}=***`);
}

/**
 * Retry a synchronous function with exponential backoff.
 * Used for migrations and schema push to handle transient network failures.
 */
function withRetry(
  fn: () => void,
  label: string,
  maxAttempts: number = 3,
  backoffMs: number[] = [1000, 2000, 4000]
): void {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      fn();
      return;
    } catch (error) {
      if (attempt === maxAttempts) throw error;
      const delay = backoffMs[attempt - 1] || 4000;
      console.warn(`[DB-SETUP] ${label} failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms...`);
      execSync(`sleep ${delay / 1000}`);
    }
  }
}

/**
 * Classify a migration error to determine if fallback to db push is safe.
 * Returns: "safe_to_push" | "critical" | "connection"
 */
function classifyMigrationError(error: unknown): "safe_to_push" | "critical" | "connection" {
  const message = error instanceof Error ? error.message : String(error);

  // P3005: migration already applied — safe to push
  // P3006: no migration history — safe to push (e.g., fresh SQLite)
  if (message.includes("P3005") || message.includes("P3006") || message.includes("No migration")) {
    return "safe_to_push";
  }

  // P3009: dirty migration state — CRITICAL, do NOT push
  if (message.includes("P3009") || message.includes("dirty")) {
    return "critical";
  }

  // P1001: can't reach database — connection issue
  if (message.includes("P1001") || message.includes("ECONNREFUSED") || message.includes("timeout")) {
    return "connection";
  }

  // Unknown errors: allow push as fallback but log warning
  return "safe_to_push";
}

/**
 * Full setup flow: update schema, generate client, run migrations.
 * Used by the web installer's /api/setup/initialize endpoint.
 */
export async function initializeDatabase(
  provider: DatabaseProvider,
  connectionUrl: string
): Promise<{ success: boolean; error?: string; alreadyInitialized?: boolean }> {
  try {
    // 0. Check if database is already initialized (A.1)
    try {
      const initialized = await isDatabaseInitialized();
      if (initialized) {
        console.log("[DB-SETUP] Database already initialized, regenerating client only...");
        generateClient();
        return { success: true, alreadyInitialized: true };
      }
    } catch {
      // isDatabaseInitialized may fail if env isn't set yet — continue with full setup
    }

    // 1. Test the connection first
    const testResult = await validateConnection(connectionUrl, provider);
    if (!testResult.success) {
      return { success: false, error: testResult.error };
    }

    // 2. Update .env with new connection info
    await updateEnvFile("DATABASE_URL", connectionUrl);
    await updateEnvFile("DATABASE_PROVIDER", provider);

    // 3. Update schema provider
    await updateSchemaProvider(provider);

    // 4. Generate prisma client
    generateClient();

    // 4.5. Check if database exists, create if needed (A.3)
    const buildProvider = (
      process.env.DATABASE_PROVIDER || "postgresql"
    ).toLowerCase() as DatabaseProvider;
    const providerChanged = provider !== buildProvider;

    if (providerChanged && provider !== "sqlite") {
      // The in-process client was generated for the previous provider and
      // cannot speak this protocol — create the database via the freshly
      // generated CLI instead (best-effort: db push validates afterwards).
      try {
        const url = new URL(connectionUrl);
        const dbName = url.pathname.replace(/^\//, "");
        if (dbName) {
          const rootUrl = new URL(connectionUrl);
          rootUrl.pathname = provider === "postgresql" ? "/postgres" : "/";
          const stmt =
            provider === "mysql"
              ? `CREATE DATABASE IF NOT EXISTS \`${dbName.replace(/`/g, "")}\`;`
              : `CREATE DATABASE "${dbName.replace(/"/g, "")}";`;
          execSync(
            `printf '%s' '${stmt}' | npx prisma db execute --url '${rootUrl.toString()}' --stdin`,
            { stdio: "pipe", cwd: process.cwd() }
          );
          console.log("[DB-SETUP] Database ensured via CLI.");
        }
      } catch {
        console.warn(
          "[DB-SETUP] Could not pre-create database (may already exist); continuing to db push."
        );
      }
    } else if (provider !== "sqlite") {
      const dbCheck = await checkDatabaseExists(connectionUrl, provider);
      if (!dbCheck.exists) {
        console.log("[DB-SETUP] Database does not exist, attempting to create...");
        const createResult = await createDatabase(connectionUrl, provider);
        if (!createResult.success) {
          return { success: false, error: `No se pudo crear la base de datos: ${createResult.error}` };
        }
        console.log("[DB-SETUP] Database created successfully.");
      }
    }

    // 5. Apply migrations with retry and error classification (A.2 + A.5)
    if (provider !== "postgresql") {
      // The migrations in prisma/migrations are PostgreSQL-flavored SQL —
      // replaying them on MySQL/MariaDB/SQLite would fail mid-migration and
      // leave a dirty P3009 state. This is a fresh install by definition,
      // so push the schema directly instead.
      withRetry(() => pushSchema(), "db push");
    } else {
      try {
        withRetry(() => runMigrations(), "migrate deploy");
      } catch (migrateError) {
        const classification = classifyMigrationError(migrateError);

        if (classification === "critical") {
          const msg = migrateError instanceof Error ? migrateError.message : String(migrateError);
          return {
            success: false,
            error: `Error crítico en migraciones (estado dirty): ${msg}. Ejecuta 'prisma migrate resolve' manualmente.`,
          };
        }

        if (classification === "connection") {
          const msg = migrateError instanceof Error ? migrateError.message : String(migrateError);
          return {
            success: false,
            error: `No se pudo conectar a la base de datos durante las migraciones: ${msg}`,
          };
        }

        // safe_to_push: fallback to db push
        console.warn("[DB-SETUP] Migrate failed (safe to push), trying db push...");
        withRetry(() => pushSchema(), "db push");
      }
    }

    return { success: true };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown setup error";
    return { success: false, error: message };
  }
}

/**
 * CLI entry point when run as: npx tsx src/lib/infrastructure/db-setup.ts
 *
 * Usage:
 *   npx tsx src/lib/infrastructure/db-setup.ts --provider=sqlite --url=file:./prisma/dev.db
 *   npx tsx src/lib/infrastructure/db-setup.ts --provider=postgresql --url=postgresql://user:pass@localhost:5432/aetheria
 */
async function main() {
  const args = process.argv.slice(2);
  const providerArg = args.find((a) => a.startsWith("--provider="));
  const urlArg = args.find((a) => a.startsWith("--url="));

  if (!providerArg || !urlArg) {
    console.error("Usage: tsx src/lib/infrastructure/db-setup.ts --provider=<postgresql|sqlite|mysql> --url=<connection_url>");
    process.exit(1);
  }

  const provider = providerArg.split("=")[1] as DatabaseProvider;
  const url = urlArg.split("=")[1];

  if (!["postgresql", "sqlite", "mysql"].includes(provider)) {
    console.error(`Invalid provider: ${provider}. Must be postgresql, sqlite, or mysql.`);
    process.exit(1);
  }

  console.log(`[DB-SETUP] Initializing ${provider} database...`);
  console.log(`[DB-SETUP] Connection URL: ${url.replace(/:[^:@]+@/, ":****@")}`);

  const result = await initializeDatabase(provider, url);

  if (result.success) {
    console.log("[DB-SETUP] Database initialized successfully!");
    console.log("[DB-SETUP] You can now run: npm run db:seed");
  } else {
    console.error("[DB-SETUP] Setup failed:", result.error);
    process.exit(1);
  }
}

// Run main if executed directly
if (require.main === module) {
  main().catch((error) => {
    console.error("[DB-SETUP] Fatal error:", error);
    process.exit(1);
  });
}

export { type DatabaseProvider };

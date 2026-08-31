import { NextRequest, NextResponse } from "next/server";
import { type DatabaseProvider, getPrisma, resolveReachableUrl } from "@/lib/infrastructure/db-adapter";
import { initializeDatabase } from "@/lib/infrastructure/db-setup";
import { resetPrismaClient } from "@/lib/db";

export const dynamic = "force-dynamic";
export const maxDuration = 120; // Allow up to 2 minutes for migrations

/**
 * Check if setup is already complete.
 * Returns false if the DB is not accessible (setup not done yet).
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
 * Try to clear the @prisma/client module cache so the regenerated
 * client is used. Works in CommonJS context.
 */
function clearPrismaClientCache(): void {
  try {
    // Attempt to clear the Prisma client module cache
    const modulePath = require.resolve("@prisma/client");
    if (require.cache[modulePath]) {
      delete require.cache[modulePath];
    }
  } catch {
    // ES module context or cache not available — non-critical
  }
}

/**
 * POST /api/setup/initialize
 *
 * Body: { provider, connectionUrl }
 *
 * Initializes the database:
 * 1. Updates .env with DATABASE_URL and DATABASE_PROVIDER
 * 2. Updates prisma schema provider
 * 3. Runs prisma generate + migrate deploy
 * 4. Resets the PrismaClient singleton
 *
 * Returns: { success: boolean, requiresRestart?: boolean, error?: string }
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
    const connectionUrl = body.connectionUrl as string;

    if (!provider || !["postgresql", "sqlite", "mysql"].includes(provider)) {
      return NextResponse.json(
        { success: false, error: "Invalid or missing provider" },
        { status: 400 }
      );
    }

    if (!connectionUrl) {
      return NextResponse.json(
        { success: false, error: "Connection URL is required" },
        { status: 400 }
      );
    }

    const currentProvider = process.env.DATABASE_PROVIDER || "postgresql";
    const providerChanged = provider !== currentProvider;

    // Docker-aware host resolution: "localhost" from inside a container is
    // the app container itself. Resolve to a reachable host (container name,
    // docker host gateway) and persist THAT url.
    let effectiveUrl = connectionUrl;
    let hostNote: string | undefined;
    if (provider !== "sqlite") {
      const resolved = await resolveReachableUrl(connectionUrl, provider);
      if (!resolved) {
        return NextResponse.json(
          {
            success: false,
            error:
              "Cannot reach the database server from this container. If it runs in Docker, use the container/service name (e.g. aetheria-db) instead of localhost.",
          },
          { status: 400 }
        );
      }
      effectiveUrl = resolved.url;
      if (resolved.resolvedHost !== resolved.originalHost) {
        hostNote = `Host "${resolved.originalHost}" no era alcanzable; usando "${resolved.resolvedHost}".`;
      }
    }

    // Run the full initialization (updates .env, schema, generates client, runs migrations)
    const result = await initializeDatabase(provider, effectiveUrl);

    if (!result.success) {
      return NextResponse.json(result, { status: 500 });
    }

    // Update process.env so the new PrismaClient picks up the new URL
    process.env.DATABASE_URL = effectiveUrl;
    process.env.DATABASE_PROVIDER = provider;

    // If the provider changed, the Prisma client was regenerated.
    // Clear the module cache and reset the singleton.
    if (providerChanged) {
      clearPrismaClientCache();
    }

    // Reset the PrismaClient singleton to pick up the new connection
    await resetPrismaClient();

    // Verify the new client works
    let clientWorks = false;
    try {
      const client = getPrisma();
      await client.$connect();
      // Try a simple query
      await client.$queryRaw`SELECT 1 as ok`;
      clientWorks = true;

      // Mark the current setup step
      await client.systemConfig.upsert({
        where: { key: "setup_step" },
        update: { value: "admin" },
        create: { key: "setup_step", value: "admin" },
      });
    } catch {
      // Client doesn't work with the new config — server restart needed
      clientWorks = false;
    }

    return NextResponse.json({
      success: true,
      requiresRestart: providerChanged && !clientWorks,
    });
  } catch (error) {
    console.error("[SETUP] Initialize error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

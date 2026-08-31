import { NextRequest, NextResponse } from "next/server";
import { getPrisma } from "@/lib/infrastructure/db-adapter";
import { hashPassword } from "@/lib/crypto";
import { generateSrpCredentials } from "@/lib/auth/srp-credentials";

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
 * POST /api/setup/create-admin
 *
 * Body: { name, email, password }
 *
 * Creates the first system admin user.
 * - Hashes password with bcrypt (12 rounds)
 * - Sets isSystemAdmin = true
 * - Also creates basic system config entries if they don't exist
 *
 * Returns: { success: boolean, userId?: string, error?: string }
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
    const { firstName, lastName, email, password } = body;

    // Validate input
    if (!firstName?.trim() || !email?.trim() || !password) {
      return NextResponse.json(
        { success: false, error: "First name, email, and password are required" },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return NextResponse.json(
        { success: false, error: "Password must be at least 8 characters" },
        { status: 400 }
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return NextResponse.json(
        { success: false, error: "Invalid email format" },
        { status: 400 }
      );
    }

    const client = getPrisma();

    // Check if a system admin already exists
    const existingAdmin = await client.user.findFirst({
      where: { isSystemAdmin: true },
      select: { id: true },
    });

    // Individual mode: the single internal workspace is auto-created with the
    // admin — no company step, no plans, everything unlocked by default.
    async function ensureWorkspace(): Promise<string> {
      const existing = await client.company.findFirst({
        where: { slug: "aetheria-individual" },
        select: { id: true },
      });
      if (existing) return existing.id;
      const created = await client.company.create({
        data: {
          name: "Aetheria Individual",
          slug: "aetheria-individual",
          email: "admin@individual.local",
          isActive: true,
        },
        select: { id: true },
      });
      return created.id;
    }

    if (existingAdmin) {
      // Admin already exists — ensure workspace + step, allow continuing
      await ensureWorkspace();
      await client.systemConfig.upsert({
        where: { key: "setup_step" },
        update: { value: "ai" },
        create: { key: "setup_step", value: "ai" },
      });

      return NextResponse.json({
        success: true,
        userId: existingAdmin.id,
        message: "Admin account already exists",
      });
    }

    // Check if email is already taken
    const existingUser = await client.user.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });

    if (existingUser) {
      return NextResponse.json(
        { success: false, error: "A user with this email already exists" },
        { status: 409 }
      );
    }

    // Hash the password with bcrypt + generate SRP credentials
    // (the login page authenticates via SRP — without salt/verifier the
    // account could never sign in)
    const passwordHash = await hashPassword(password);
    const { srpSalt, srpVerifier } = generateSrpCredentials(normalizedEmail, password);

    // Auto-create the internal workspace first so the admin can be linked
    const workspaceId = await ensureWorkspace();

    // Create the system admin user, linked to the workspace
    const user = await client.user.create({
      data: {
        email: normalizedEmail,
        passwordHash,
        srpSalt,
        srpVerifier,
        firstName: firstName.trim(),
        lastName: lastName?.trim() || "",
        isSystemAdmin: true,
        isActive: true,
        emailVerified: new Date(),
        preferredLanguage: "en",
        theme: "dark",
        companyId: workspaceId,
      },
    });

    // Create basic system config entries if they don't exist
    const defaultConfigs = [
      { key: "site_name", value: "AETHERIA" },
      { key: "site_tagline", value: "Personal AI Security Platform" },
      { key: "default_language", value: "en" },
      { key: "maintenance_mode", value: false },
      { key: "enforce_2fa_admins", value: false },
      { key: "max_file_size_mb", value: 1024 },
      { key: "rate_limit_enabled", value: true },
    ];

    for (const config of defaultConfigs) {
      await client.systemConfig.upsert({
        where: { key: config.key },
        update: {},
        create: { key: config.key, value: config.value as never },
      });
    }

    // Update setup step — next is AI provider (no company step in individual mode)
    await client.systemConfig.upsert({
      where: { key: "setup_step" },
      update: { value: "ai" },
      create: { key: "setup_step", value: "ai" },
    });

    // Create audit log
    await client.auditLog.create({
      data: {
        action: "setup_create_admin",
        entityType: "User",
        entityId: user.id,
        userId: user.id,
        ipAddress: request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown",
      },
    });

    return NextResponse.json({
      success: true,
      userId: user.id,
    });
  } catch (error) {
    console.error("[SETUP] Create admin error:", error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

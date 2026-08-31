import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { srpServerStep1 } from "@/lib/srp-server";

// In-memory storage for server ephemeral keys (expires after 5 minutes)
const serverEphemeralStore = new Map<string, { secret: string; expiresAt: number }>();

// Cleanup expired ephemerals every minute
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of serverEphemeralStore.entries()) {
    if (now > data.expiresAt) {
      serverEphemeralStore.delete(email);
    }
  }
}, 60_000);

/**
 * POST /api/auth/srp/step1
 * Client sends: { email, clientPublicEphemeral }
 * Server responds: { salt, serverPublicEphemeral }
 *
 * This is the first step of SRP authentication
 */
export async function POST(request: NextRequest) {
  try {
    const { email, clientPublicEphemeral } = await request.json();

    if (!email || !clientPublicEphemeral) {
      return NextResponse.json(
        { error: "Email and clientPublicEphemeral required" },
        { status: 400 }
      );
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      select: {
        id: true,
        srpSalt: true,
        srpVerifier: true,
        isBlocked: true,
        lockoutUntil: true,
      },
    });

    // If user not found or no SRP credentials, return error
    // NOTE: In production, you might want to return a fake salt/ephemeral
    // to avoid leaking which users exist (timing attack prevention)
    if (!user || !user.srpSalt || !user.srpVerifier) {
      return NextResponse.json(
        { error: "Invalid credentials or SRP not configured" },
        { status: 401 }
      );
    }

    if (user.isBlocked) {
      return NextResponse.json({ error: "Account is blocked" }, { status: 403 });
    }

    if (user.lockoutUntil && user.lockoutUntil > new Date()) {
      return NextResponse.json(
        { error: "Account is temporarily locked" },
        { status: 403 }
      );
    }

    // Generate server ephemeral
    const serverEphemeral = srpServerStep1(user.srpVerifier);

    // Store server secret ephemeral for step 2 (expires in 5 minutes)
    serverEphemeralStore.set(email.toLowerCase(), {
      secret: serverEphemeral.secret,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // Return salt and server public ephemeral to client
    return NextResponse.json({
      salt: user.srpSalt,
      serverPublicEphemeral: serverEphemeral.public,
    });
  } catch (error) {
    console.error("[SRP Step 1] Error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * Internal function to peek at the server ephemeral WITHOUT consuming it.
 * Needed for the 2FA round-trip: the client first proves the password,
 * then re-sends the same proof together with the TOTP code.
 */
export function peekServerEphemeral(email: string): string | null {
  const data = serverEphemeralStore.get(email.toLowerCase());
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    serverEphemeralStore.delete(email.toLowerCase());
    return null;
  }
  return data.secret;
}

/** Consume the ephemeral after a fully successful authentication. */
export function consumeServerEphemeral(email: string): void {
  serverEphemeralStore.delete(email.toLowerCase());
}

/**
 * Internal function to retrieve and consume server ephemeral
 */
export function getServerEphemeral(email: string): string | null {
  const data = serverEphemeralStore.get(email.toLowerCase());
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    serverEphemeralStore.delete(email.toLowerCase());
    return null;
  }
  // Consume the ephemeral (one-time use)
  serverEphemeralStore.delete(email.toLowerCase());
  return data.secret;
}

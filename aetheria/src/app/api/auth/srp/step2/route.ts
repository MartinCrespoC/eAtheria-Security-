import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { srpServerStep2 } from "@/lib/srp-server";
import { peekServerEphemeral, consumeServerEphemeral } from "../step1/route";
import { sign } from "jsonwebtoken";
import speakeasy from "speakeasy";

/**
 * POST /api/auth/srp/step2
 * Client sends: { email, clientPublicEphemeral, clientProof }
 * Server responds: { serverProof, sessionToken } or error
 *
 * This is the final step of SRP authentication
 * If successful, returns a JWT session token
 */
export async function POST(request: NextRequest) {
  try {
    const { email, clientPublicEphemeral, clientProof, totpCode } = await request.json();

    if (!email || !clientPublicEphemeral || !clientProof) {
      return NextResponse.json(
        { error: "Email, clientPublicEphemeral, and clientProof required" },
        { status: 400 }
      );
    }

    // Peek at the server ephemeral WITHOUT consuming it — if 2FA is enabled
    // the client must make a second request with the same proof + TOTP code.
    // It is consumed only when the full authentication succeeds.
    const serverSecretEphemeral = peekServerEphemeral(email.toLowerCase());
    if (!serverSecretEphemeral) {
      return NextResponse.json(
        { error: "Invalid or expired session. Please restart login." },
        { status: 401 }
      );
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        srpSalt: true,
        srpVerifier: true,
        isBlocked: true,
        lockoutUntil: true,
        failedLoginAttempts: true,
        isSystemAdmin: true,
        twoFactorEnabled: true,
        twoFactorSecret: true,
        companyId: true,
        avatarUrl: true,
        theme: true,
      },
    });

    if (!user || !user.srpSalt || !user.srpVerifier) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
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

    // Verify client proof and derive server session
    const serverSession = srpServerStep2(
      serverSecretEphemeral,
      clientPublicEphemeral,
      user.srpSalt,
      user.email,
      user.srpVerifier,
      clientProof
    );

    if (!serverSession) {
      // Invalid proof = wrong password
      const failed = user.failedLoginAttempts + 1;
      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: failed,
          lockoutUntil:
            failed >= 5
              ? new Date(Date.now() + 15 * 60 * 1000) // 15 min lockout
              : undefined,
        },
      });
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    // Password proof is valid. If 2FA is enabled, require the TOTP code
    // before issuing the session token. The first request (no code) tells
    // the client to prompt for it; the ephemeral stays alive for the retry.
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!totpCode) {
        return NextResponse.json({ requiresTwoFactor: true });
      }
      const totpValid = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: String(totpCode),
        window: 2,
      });
      if (!totpValid) {
        return NextResponse.json(
          { error: "Código 2FA inválido" },
          { status: 401 }
        );
      }
    }

    // Authentication successful — consume the one-time ephemeral
    consumeServerEphemeral(email.toLowerCase());

    // Reset failed attempts and update last login
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockoutUntil: null,
        lastLoginAt: new Date(),
      },
    });

    // Generate temporary auth token (valid for 1 minute)
    // This will be used to authenticate with NextAuth
    const secret = process.env.NEXTAUTH_SECRET;
    if (!secret) {
      console.error("[SRP Step 2] NEXTAUTH_SECRET not configured — refusing to sign token");
      return NextResponse.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }
    const authToken = sign(
      {
        email: user.email,
        srpVerified: true,
        timestamp: Date.now(),
      },
      secret,
      { expiresIn: "1m" }
    );

    // Return server proof and temporary auth token
    return NextResponse.json({
      serverProof: serverSession.proof,
      authToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isSystemAdmin: user.isSystemAdmin,
      },
    });
  } catch (error) {
    console.error("[SRP Step 2] Error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

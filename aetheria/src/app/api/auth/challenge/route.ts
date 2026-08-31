import { NextResponse } from "next/server";
import crypto from "crypto";

// In-memory challenge store (expires after 5 minutes)
const challenges = new Map<string, { challenge: string; expiresAt: number }>();

// Cleanup expired challenges every minute
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of challenges.entries()) {
    if (now > data.expiresAt) {
      challenges.delete(email);
    }
  }
}, 60_000);

/**
 * GET /api/auth/challenge?email=xxx
 * Returns a cryptographic challenge (nonce) for the given email
 * The client will use this to hash the password before transmission
 */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const email = searchParams.get("email");

  if (!email) {
    return NextResponse.json({ error: "Email required" }, { status: 400 });
  }

  // Generate a random challenge (32 bytes = 256 bits)
  const challenge = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

  challenges.set(email.toLowerCase(), { challenge, expiresAt });

  return NextResponse.json({ challenge });
}

/**
 * Internal function to verify and consume a challenge
 * Called by the auth handler during login
 */
export function verifyChallenge(email: string): string | null {
  const data = challenges.get(email.toLowerCase());
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    challenges.delete(email.toLowerCase());
    return null;
  }
  // Consume the challenge (one-time use)
  challenges.delete(email.toLowerCase());
  return data.challenge;
}

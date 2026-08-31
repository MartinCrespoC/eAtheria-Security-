/**
 * SRP (Secure Remote Password) Server Implementation
 * Zero-knowledge password authentication
 *
 * The server NEVER sees the password in plaintext
 * The password is NEVER transmitted over the network
 */

import * as srp from "secure-remote-password/server";

export interface SRPEphemeral {
  secret: string;
  public: string;
}

/**
 * Step 1: Server generates ephemeral key pair for this login session
 * Called when client initiates login with their public ephemeral
 */
export function srpServerStep1(verifier: string): SRPEphemeral {
  return srp.generateEphemeral(verifier);
}

/**
 * Step 2: Server derives session key and verifies client proof
 * Returns server proof if client is authenticated, null if invalid
 */
export function srpServerStep2(
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  salt: string,
  username: string,
  verifier: string,
  clientProof: string
): { proof: string; key: string } | null {
  try {
    const serverSession = srp.deriveSession(
      serverSecretEphemeral,
      clientPublicEphemeral,
      salt,
      username,
      verifier,
      clientProof
    );

    return serverSession;
  } catch (error) {
    // Invalid proof = wrong password
    console.error("[SRP] Authentication failed:", error);
    return null;
  }
}

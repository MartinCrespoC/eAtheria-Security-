/**
 * SRP (Secure Remote Password) Client Implementation
 * Zero-knowledge password authentication
 *
 * The password NEVER leaves the browser
 * The server NEVER sees the password
 */

import * as srp from "secure-remote-password/client";

export interface SRPEphemeral {
  secret: string;
  public: string;
}

export interface SRPSession {
  key: string;
  proof: string;
}

/**
 * Generate salt and verifier for registration
 * Called when creating a new account
 */
export function srpGenerateRegistration(username: string, password: string): {
  salt: string;
  verifier: string;
} {
  const salt = srp.generateSalt();
  const privateKey = srp.derivePrivateKey(salt, username, password);
  const verifier = srp.deriveVerifier(privateKey);

  return { salt, verifier };
}

/**
 * Step 1: Client generates ephemeral key pair
 * Called at the start of login
 */
export function srpClientStep1(): SRPEphemeral {
  return srp.generateEphemeral();
}

/**
 * Step 2: Client derives session key and generates proof
 * This proves to the server that the client knows the password
 * WITHOUT revealing the password
 */
export function srpClientStep2(
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  password: string
): SRPSession {
  const privateKey = srp.derivePrivateKey(salt, username, password);
  const clientSession = srp.deriveSession(
    clientSecretEphemeral,
    serverPublicEphemeral,
    salt,
    username,
    privateKey
  );

  return clientSession;
}

/**
 * Step 3: Client verifies server proof
 * This proves to the client that the server has the correct verifier
 * Prevents man-in-the-middle attacks
 */
export function srpClientStep3(
  clientPublicEphemeral: string,
  clientSession: SRPSession,
  serverProof: string
): void {
  srp.verifySession(clientPublicEphemeral, clientSession, serverProof);
}

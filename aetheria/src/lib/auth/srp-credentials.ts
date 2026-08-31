import { generateSalt, derivePrivateKey, deriveVerifier } from "secure-remote-password/client";

/**
 * Generates the SRP salt + verifier for a new user (or password change).
 * The login flow requires these on the user record; without them the
 * account can never authenticate via the SRP login page.
 */
export function generateSrpCredentials(email: string, password: string): {
  srpSalt: string;
  srpVerifier: string;
} {
  const srpSalt = generateSalt();
  const privateKey = derivePrivateKey(srpSalt, email.toLowerCase().trim(), password);
  const srpVerifier = deriveVerifier(privateKey);
  return { srpSalt, srpVerifier };
}

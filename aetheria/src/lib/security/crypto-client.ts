/**
 * Client-side cryptography utilities
 * Used to hash passwords before transmission to prevent plaintext exposure
 */

/**
 * Hash password using PBKDF2 with a server-provided challenge
 * This ensures passwords are never sent in plaintext over the network
 */
export async function hashPasswordClient(
  password: string,
  challenge: string
): Promise<string> {
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  const saltData = encoder.encode(challenge);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordData,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  // Derive bits using PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltData,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  // Convert to hex string
  const hashArray = Array.from(new Uint8Array(derivedBits));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

import speakeasy from "speakeasy";
import QRCode from "qrcode";

export function generate2FASecret(email: string) {
  const secret = speakeasy.generateSecret({
    name: `EATHERIA (${email})`,
    issuer: "EATHERIA Security",
    length: 32,
  });

  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url || "",
  };
}

export async function generateQRCode(otpauthUrl: string): Promise<string> {
  return QRCode.toDataURL(otpauthUrl);
}

export function verify2FAToken(secret: string, token: string): boolean {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 2,
  });
}

export function generateBackupCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    codes.push(code.match(/.{1,4}/g)?.join("-") || code);
  }
  return codes;
}

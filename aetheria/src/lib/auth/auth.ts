import { NextAuthOptions, getServerSession } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "@/lib/db";
import { verifyPassword } from "@/lib/crypto";
import speakeasy from "speakeasy";
import { verify } from "jsonwebtoken";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      companyId?: string | null;
      isSystemAdmin: boolean;
      isCompanyAdmin: boolean;
      twoFactorEnabled: boolean;
      avatarUrl?: string | null;
      theme?: string;
      locale?: string;
    };
  }

  interface User {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    companyId?: string | null;
    isSystemAdmin: boolean;
    isCompanyAdmin: boolean;
    twoFactorEnabled: boolean;
    avatarUrl?: string | null;
    isBlocked?: boolean;
    theme?: string;
    locale?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    companyId?: string | null;
    isSystemAdmin: boolean;
    isCompanyAdmin: boolean;
    twoFactorEnabled: boolean;
    avatarUrl?: string | null;
    isBlocked?: boolean;
    theme?: string;
    locale?: string;
  }
}

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma) as never,
  session: { strategy: "jwt", maxAge: 24 * 60 * 60 },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  cookies: {
    sessionToken: {
      name: "next-auth.session-token",
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
        passwordHash: { label: "Password Hash", type: "text" },
        srpProof: { label: "SRP Proof", type: "text" },
        totpCode: { label: "2FA Code", type: "text" },
      },
      async authorize(credentials) {
        if (!credentials?.email || (!credentials?.password && !credentials?.passwordHash && !credentials?.srpProof)) {
          throw new Error("Email and password are required");
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email.toLowerCase() },
        });

        if (!user) {
          throw new Error("Invalid credentials");
        }

        // Check if user has any auth method configured
        if (!user.passwordHash && !user.srpSalt && !user.srpVerifier) {
          throw new Error("No authentication method configured");
        }

        if (user.isBlocked) {
          throw new Error("Account is blocked");
        }

        if (user.lockoutUntil && user.lockoutUntil > new Date()) {
          throw new Error("Account is temporarily locked");
        }

        let isValid = false;

        // Check if client sent SRP auth token (zero-knowledge auth)
        if (credentials.srpProof) {
          try {
            const decoded = verify(
              credentials.srpProof,
              process.env.NEXTAUTH_SECRET || ""
            ) as { email: string; srpVerified: boolean; timestamp: number };

            if (decoded.srpVerified && decoded.email === credentials.email.toLowerCase()) {
              isValid = true;
            }
          } catch {
            throw new Error("Invalid SRP authentication");
          }
        } else if (credentials.password && user.passwordHash) {
          // Fallback: plaintext password (legacy, for users without SRP)
          isValid = await verifyPassword(
            credentials.password,
            user.passwordHash
          );

          // Transparent migration: enroll SRP credentials so the next
          // login uses zero-knowledge auth.
          if (isValid && (!user.srpSalt || !user.srpVerifier)) {
            try {
              const { generateSrpCredentials } = await import("./srp-credentials");
              const creds = generateSrpCredentials(credentials.email, credentials.password);
              await prisma.user.update({ where: { id: user.id }, data: creds });
            } catch (e) {
              console.error("[AUTH] SRP enrollment failed (non-blocking):", e);
            }
          }
        }

        if (!isValid) {
          // Increment failed attempts
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
          throw new Error("Invalid credentials");
        }

        // Check 2FA if enabled.
        // NOTE: SRP logins (srpProof) already verified the TOTP code in
        // /api/auth/srp/step2 BEFORE the authToken was signed — requiring it
        // again here would make every 2FA login fail. This check only guards
        // the legacy plaintext/bcrypt path below.
        if (user.twoFactorEnabled && user.twoFactorSecret && !credentials.srpProof) {
          if (!credentials.totpCode) {
            throw new Error("2FA_REQUIRED");
          }

          const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: "base32",
            token: credentials.totpCode,
            window: 2,
          });

          if (!verified) {
            throw new Error("Invalid 2FA code");
          }
        }

        // Reset failed attempts and update last login
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: 0,
            lockoutUntil: null,
            lastLoginAt: new Date(),
          },
        });

        return {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          companyId: user.companyId,
          isSystemAdmin: user.isSystemAdmin,
          isCompanyAdmin: user.isCompanyAdmin,
          twoFactorEnabled: user.twoFactorEnabled,
          avatarUrl: user.avatarUrl,
          isBlocked: user.isBlocked,
          theme: user.theme,
          locale: user.preferredLanguage,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.firstName = user.firstName;
        token.lastName = user.lastName;
        token.companyId = user.companyId;
        token.isSystemAdmin = user.isSystemAdmin;
        token.isCompanyAdmin = user.isCompanyAdmin;
        token.twoFactorEnabled = user.twoFactorEnabled;
        token.avatarUrl = user.avatarUrl;
        token.isBlocked = user.isBlocked;
        token.theme = user.theme;
        token.locale = user.locale;
      }

      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id;
        session.user.email = token.email;
        session.user.firstName = token.firstName;
        session.user.lastName = token.lastName;
        session.user.companyId = token.companyId;
        session.user.isSystemAdmin = token.isSystemAdmin;
        session.user.isCompanyAdmin = token.isCompanyAdmin;
        session.user.twoFactorEnabled = token.twoFactorEnabled;
        session.user.avatarUrl = token.avatarUrl;
        session.user.theme = token.theme;
        session.user.locale = token.locale;
      }
      return session;
    },
  },
};

export const auth = () => getServerSession(authOptions);

export async function requireAuth() {
  const session = await auth();
  if (!session?.user) {
    throw new Error("UNAUTHORIZED");
  }
  return session;
}

export async function requireSystemAdmin() {
  const session = await requireAuth();
  if (!session.user.isSystemAdmin) {
    throw new Error("FORBIDDEN");
  }
  return session;
}

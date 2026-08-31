import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/db";
import { hashPassword } from "@/lib/crypto";
import { ensureDefaultRoles } from "@/lib/security/permissions";
import { logAudit, AuditAction, AuditSeverity } from "@/lib/security/audit-logger";

// ==================== GET - Validate Token ====================

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ token: string }> }
) {
  try {
    const { token } = await params;

    // Look up invite in SystemConfig
    const invite = await prisma.systemConfig.findUnique({
      where: { key: `invite:${token}` },
    });

    if (!invite) {
      return NextResponse.json(
        { error: "Invitación no encontrada o expirada" },
        { status: 404 }
      );
    }

    const inviteData = invite.value as {
      email: string;
      companyId: string;
      invitedBy: string;
      roleId?: string;
      firstName?: string;
      lastName?: string;
      expiresAt: string;
      accepted: boolean;
    };

    // Check if expired
    if (new Date(inviteData.expiresAt) < new Date()) {
      await prisma.systemConfig.delete({
        where: { key: `invite:${token}` },
      }).catch(() => {});
      return NextResponse.json(
        { error: "La invitación ha expirado" },
        { status: 410 }
      );
    }

    // Check if already accepted
    if (inviteData.accepted) {
      return NextResponse.json(
        { error: "Esta invitación ya fue utilizada" },
        { status: 410 }
      );
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: inviteData.email },
      select: { id: true, companyId: true },
    });

    return NextResponse.json({
      email: inviteData.email,
      firstName: inviteData.firstName || "",
      lastName: inviteData.lastName || "",
      existingUser: !!existingUser,
      roleId: inviteData.roleId,
    });
  } catch (error) {
    console.error("Error validating invite:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

// ==================== POST - Accept Invite ====================

const acceptInviteSchema = z.object({
  password: z.string().min(8, "Password must be at least 8 characters"),
  firstName: z.string().min(1, "First name required").max(100).optional(),
  lastName: z.string().min(1, "Last name required").max(100).optional(),
});

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ token: string }> }
) {
  try {
    const { token } = await params;

    // Look up invite
    const invite = await prisma.systemConfig.findUnique({
      where: { key: `invite:${token}` },
    });

    if (!invite) {
      return NextResponse.json(
        { error: "Invitación no encontrada o expirada" },
        { status: 404 }
      );
    }

    const inviteData = invite.value as {
      email: string;
      companyId: string;
      invitedBy: string;
      roleId?: string;
      firstName?: string;
      lastName?: string;
      expiresAt: string;
      accepted: boolean;
    };

    // Check if expired
    if (new Date(inviteData.expiresAt) < new Date()) {
      await prisma.systemConfig.delete({
        where: { key: `invite:${token}` },
      }).catch(() => {});
      return NextResponse.json(
        { error: "La invitación ha expirado" },
        { status: 410 }
      );
    }

    // Check if already accepted
    if (inviteData.accepted) {
      return NextResponse.json(
        { error: "Esta invitación ya fue utilizada" },
        { status: 410 }
      );
    }

    const body = await request.json();
    const parsed = acceptInviteSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: parsed.error.issues[0]?.message || "Invalid input" },
        { status: 400 }
      );
    }

    const { password, firstName, lastName } = parsed.data;

    // Ensure roles exist for the company
    await ensureDefaultRoles(inviteData.companyId);

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: inviteData.email },
    });

    if (existingUser) {
      // User exists - add to company with role
      await prisma.user.update({
        where: { id: existingUser.id },
        data: {
          companyId: inviteData.companyId,
          isActive: true,
          isBlocked: false,
          firstName: firstName || existingUser.firstName,
          lastName: lastName || existingUser.lastName,
        },
      });

      // Assign role
      if (inviteData.roleId) {
        // Remove old roles from this company (if any)
        const oldRoles = await prisma.role.findMany({
          where: { companyId: inviteData.companyId },
          select: { id: true },
        });

        if (oldRoles.length > 0) {
          await prisma.userRole.deleteMany({
            where: {
              userId: existingUser.id,
              roleId: { in: oldRoles.map((r) => r.id) },
            },
          });
        }

        await prisma.userRole.create({
          data: { userId: existingUser.id, roleId: inviteData.roleId },
        });
      }
    } else {
      // Create new user
      const passwordHash = await hashPassword(password);

      const newUser = await prisma.user.create({
        data: {
          email: inviteData.email,
          passwordHash,
          firstName: firstName || inviteData.firstName || "User",
          lastName: lastName || inviteData.lastName || "",
          companyId: inviteData.companyId,
          isActive: true,
        },
      });

      // Assign role
      if (inviteData.roleId) {
        await prisma.userRole.create({
          data: { userId: newUser.id, roleId: inviteData.roleId },
        });
      }
    }

    // Mark invite as accepted
    await prisma.systemConfig.update({
      where: { key: `invite:${token}` },
      data: {
        value: {
          ...inviteData,
          accepted: true,
          acceptedAt: new Date().toISOString(),
        } as never,
      },
    });

    await logAudit({
      action: AuditAction.REGISTER,
      severity: AuditSeverity.INFO,
      companyId: inviteData.companyId,
      metadata: {
        email: inviteData.email,
        method: "invite_acceptance",
        invitedBy: inviteData.invitedBy,
      },
      success: true,
    });

    return NextResponse.json({
      success: true,
      message: "Invitación aceptada correctamente",
      redirect: "/login",
    });
  } catch (error) {
    console.error("Error accepting invite:", error);
    return NextResponse.json(
      { error: "Error interno del servidor" },
      { status: 500 }
    );
  }
}

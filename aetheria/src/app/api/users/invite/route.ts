import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { hashPassword } from "@/lib/crypto";
import { sendMail, inviteUserEmail } from "@/lib/mail";
import { requirePermission } from "@/lib/security/permission-guard";
import { PERMISSIONS } from "@/lib/security/permissions";
import crypto from "crypto";

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.companyId) {
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    }

    const guard = await requirePermission(PERMISSIONS.TEAM_INVITE)(request);
    if (!guard.ok) return guard.response;

    const body = await request.json();
    const { email, firstName, lastName, roleId, role } = body;

    if (!email?.trim() || !firstName?.trim()) {
      return NextResponse.json(
        { error: "Email y nombre son obligatorios" },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existing = await prisma.user.findUnique({
      where: { email: email.trim() },
    });

    if (existing) {
      return NextResponse.json(
        { error: "Este email ya está registrado" },
        { status: 409 }
      );
    }

    // Generate temp password
    const tempPassword = crypto.randomBytes(8).toString("hex");
    const hashedPassword = await hashPassword(tempPassword);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: email.trim(),
        firstName: firstName.trim(),
        lastName: lastName?.trim() || "",
        passwordHash: hashedPassword,
        companyId: session.user.companyId,
        isActive: true,
      },
    });

    // Assign role if provided (accept roleId as UUID or role as name)
    const roleIdentifier = roleId || role;
    if (roleIdentifier) {
      // Determine if it's a UUID (roleId) or a role name (role)
      const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(roleIdentifier);
      const foundRole = isUuid
        ? await prisma.role.findFirst({ where: { id: roleIdentifier, companyId: session.user.companyId } })
        : await prisma.role.findFirst({ where: { name: roleIdentifier, companyId: session.user.companyId } });

      if (foundRole) {
        await prisma.userRole.create({
          data: { userId: user.id, roleId: foundRole.id },
        });
      }
    }

    // Send invitation email
    const loginUrl = `${request.nextUrl.origin}/login`;
    const inviterName = `${session.user.firstName} ${session.user.lastName}`;

    const company = await prisma.company.findUnique({
      where: { id: session.user.companyId },
      select: { name: true },
    });

    const emailPayload = inviteUserEmail(
      email.trim(),
      company?.name || "tu empresa",
      inviterName,
      loginUrl
    );
    await sendMail(emailPayload);

    // Audit log
    await prisma.auditLog.create({
      data: {
        action: "INVITE",
        entityType: "User",
        entityId: user.id,
        newValues: { email: user.email },
        userId: session.user.id,
        companyId: session.user.companyId,
      },
    });

    return NextResponse.json(
      { success: true, userId: user.id },
      { status: 201 }
    );
  } catch (error) {
    console.error("Invite error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

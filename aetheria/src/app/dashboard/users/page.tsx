import { prisma } from "@/lib/db";
import { requirePermission } from "@/lib/page-guards";
import { UsersManagement } from "@/components/dashboard/users-management";

export default async function UsersPage() {
  const session = await requirePermission("team:manage");

  const users = await prisma.user.findMany({
    where: { companyId: session.user.companyId! },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      isActive: true,
      isBlocked: true,
      twoFactorEnabled: true,
      lastLoginAt: true,
      createdAt: true,
      userRoles: {
        include: { role: { select: { name: true, displayName: true } } },
      },
    },
    orderBy: { createdAt: "asc" },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Usuarios</h1>
        <p className="text-text-secondary mt-1">
          Gestiona los usuarios de tu organización
        </p>
      </div>
      <UsersManagement users={users} />
    </div>
  );
}

import { prisma } from "@/lib/db";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Clock, User, AlertTriangle } from "lucide-react";
import { UnblockButton } from "./unblock-button";

export default async function AdminSecurityPage() {
  const [recentLogs, blockedUsers, failedLogins] = await Promise.all([
    prisma.auditLog.findMany({
      include: {
        user: { select: { email: true, firstName: true, lastName: true } },
        company: { select: { name: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 50,
    }),
    prisma.user.findMany({
      where: { isBlocked: true },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        failedLoginAttempts: true,
        lockoutUntil: true,
      },
    }),
    prisma.user.count({
      where: { failedLoginAttempts: { gt: 0 } },
    }),
  ]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Seguridad del Sistema</h1>
        <p className="text-text-secondary mt-1">
          Auditoría, usuarios bloqueados y eventos de seguridad
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-accent" />
              <div>
                <p className="text-sm text-text-secondary">Eventos de Auditoría</p>
                <p className="text-2xl font-bold text-text-primary">{recentLogs.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-red-400" />
              <div>
                <p className="text-sm text-text-secondary">Usuarios Bloqueados</p>
                <p className="text-2xl font-bold text-text-primary">{blockedUsers.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border bg-card">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <User className="h-8 w-8 text-amber-400" />
              <div>
                <p className="text-sm text-text-secondary">Login Fallidos</p>
                <p className="text-2xl font-bold text-text-primary">{failedLogins}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Blocked users */}
      {blockedUsers.length > 0 && (
        <Card className="border-red-500/20 bg-red-500/5">
          <CardHeader>
            <CardTitle className="text-base text-red-400">Usuarios Bloqueados</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {blockedUsers.map((u) => (
                <div key={u.id} className="flex items-center justify-between rounded-lg bg-card p-3">
                  <div>
                    <p className="text-sm text-text-primary">{u.firstName} {u.lastName}</p>
                    <p className="text-xs text-text-muted">{u.email}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <p className="text-xs text-red-400">{u.failedLoginAttempts} intentos fallidos</p>
                      {u.lockoutUntil && (
                        <p className="text-xs text-text-muted">
                          Hasta: {new Date(u.lockoutUntil).toLocaleString("es-ES")}
                        </p>
                      )}
                    </div>
                    <UnblockButton userId={u.id} />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Audit log */}
      <Card className="border-border bg-card">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="h-4 w-4 text-accent" />
            Log de Auditoría
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Acción</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Usuario</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Empresa</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-text-muted uppercase">Entidad</th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-text-muted uppercase">Fecha</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.map((log) => (
                  <tr key={log.id} className="border-b border-border">
                    <td className="px-4 py-3">
                      <Badge variant="secondary" className="text-xs">{log.action}</Badge>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-primary">
                      {log.user ? `${log.user.firstName} ${log.user.lastName}` : "Sistema"}
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">
                      {log.company?.name || "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-text-muted">
                      {log.entityType && (
                        <span>{log.entityType} {log.entityId ? `#${log.entityId.slice(0, 8)}` : ""}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-text-muted">
                      {new Date(log.createdAt).toLocaleString("es-ES")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

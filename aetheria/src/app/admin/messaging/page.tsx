import { requireSystemAdmin } from "@/lib/auth";
import { MessagingManager } from "@/components/admin/messaging-manager";

export default async function AdminMessagingPage() {
  await requireSystemAdmin();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Mensajería</h1>
        <p className="text-text-secondary mt-1">
          Configura canales de Telegram y WhatsApp para notificaciones
        </p>
      </div>
      <MessagingManager />
    </div>
  );
}

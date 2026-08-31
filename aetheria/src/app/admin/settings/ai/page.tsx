import { requireSystemAdmin } from "@/lib/page-guards";
import { AISettingsPanel } from "@/components/dashboard/ai-settings-panel";

export const dynamic = "force-dynamic";

export default async function AISettingsPage() {
  await requireSystemAdmin();

  return <AISettingsPanel />;
}

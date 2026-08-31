import { requireSystemAdmin } from "@/lib/auth";
import { FalsePositiveManager } from "@/components/admin/false-positive-manager";
import { HelpTooltip } from "@/components/ui/help-tooltip";
import { getHelpText } from "@/lib/i18n/translations";

export default async function FalsePositivesPage() {
  await requireSystemAdmin();

  const help = getHelpText("es", "falsePositives");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h1 className="text-3xl font-bold text-text-primary">🎯 Falsos Positivos</h1>
          <HelpTooltip
            title={help.title}
            shortHelp={help.short}
            detailedHelp={help.detailed}
            examples={[
              "console.log en desarrollo",
              "PreparedStatement en Java",
              "password_hash en PHP",
              "Patrones específicos por lenguaje",
            ]}
          />
        </div>
      </div>
      <p className="text-text-primary">
        Gestiona patrones de falsos positivos para reducir ruido en análisis
      </p>
      <FalsePositiveManager />
    </div>
  );
}

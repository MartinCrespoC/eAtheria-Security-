import { requireSystemAdmin } from "@/lib/auth";
import { DocumentationViewer } from "@/components/admin/documentation-viewer";
import { HelpTooltip } from "@/components/ui/help-tooltip";
import { getHelpText } from "@/lib/i18n/translations";

export default async function DocumentationPage() {
  await requireSystemAdmin();

  const help = getHelpText("es", "documentation");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h1 className="text-3xl font-bold text-text-primary">📚 Documentación del Sistema</h1>
          <HelpTooltip
            title={help.title}
            shortHelp={help.short}
            detailedHelp={help.detailed}
            examples={[
              "Arquitectura multi-tenant",
              "Guías de uso paso a paso",
              "Troubleshooting común",
              "API Reference completo",
              "Security best practices",
            ]}
          />
        </div>
      </div>
      <p className="text-text-primary">
        Documentación técnica completa para administradores del sistema
      </p>
      <DocumentationViewer />
    </div>
  );
}

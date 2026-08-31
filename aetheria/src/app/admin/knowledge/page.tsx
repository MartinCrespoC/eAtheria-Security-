import { requireSystemAdmin } from "@/lib/auth";
import { KnowledgeManager } from "@/components/admin/knowledge-manager";

export default async function KnowledgePage() {
  await requireSystemAdmin();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-text-primary">🧠 Base de Conocimiento</h1>
          <p className="text-text-primary mt-1">
            Gestión de skills BugHunter — 82 habilidades de caza de vulnerabilidades basadas en 681 reportes divulgados de HackerOne
          </p>
        </div>
      </div>
      <KnowledgeManager />
    </div>
  );
}

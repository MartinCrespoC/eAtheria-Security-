"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Search,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Power,
  PowerOff,
  Brain,
  Shield,
  Link2,
  AlertTriangle,
} from "lucide-react";

interface CweMapping {
  id: string;
  cweId: string;
  relevance: string;
}

interface HuntSkillData {
  id: string;
  slug: string;
  name: string;
  category: string;
  description: string;
  reportCount: number;
  cweIds: string[];
  rootCauses: { title: string; detail: string }[] | null;
  attackSignals: { type: string; pattern: string; note: string }[] | null;
  detectionPatterns: { name: string; pattern: string; language: string }[] | null;
  validationGate: { question: string; criteria: string }[] | null;
  impactExamples: { scenario: string; description: string; cveIds: string[] }[] | null;
  chains: { targetSkill: string; primitive: string }[] | null;
  bypassTechniques: string[] | null;
  frameworks: string[];
  languages: string[];
  isActive: boolean;
  lastSyncedAt: string | null;
  cweMappings: CweMapping[];
}

interface Stats {
  total: number;
  active: number;
  inactive: number;
  cweMappings: number;
  lastSync: string | null;
}

interface CategoryCount {
  category: string;
  count: number;
}

export function KnowledgeManager() {
  const [skills, setSkills] = useState<HuntSkillData[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats>({ total: 0, active: 0, inactive: 0, cweMappings: 0, lastSync: null });
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const fetchSkills = useCallback(async () => {
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: "50" });
      if (searchTerm) params.set("search", searchTerm);
      if (selectedCategory !== "all") params.set("category", selectedCategory);

      const res = await fetch(`/api/admin/knowledge?${params}`);
      const data = await res.json();

      if (data.success) {
        setSkills(data.skills);
        setStats(data.stats);
        setCategories(data.categories);
        setTotalPages(data.pagination.totalPages);
      }
    } catch (error) {
      console.error("Error fetching skills:", error);
    } finally {
      setLoading(false);
    }
  }, [page, searchTerm, selectedCategory]);

  useEffect(() => {
    fetchSkills();
  }, [fetchSkills]);

  const toggleActive = async (skillId: string, currentState: boolean) => {
    try {
      const res = await fetch("/api/admin/knowledge", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ skillId, isActive: !currentState }),
      });
      if (res.ok) {
        setSkills((prev) =>
          prev.map((s) => (s.id === skillId ? { ...s, isActive: !currentState } : s))
        );
        setStats((prev) => ({
          ...prev,
          active: currentState ? prev.active - 1 : prev.active + 1,
          inactive: currentState ? prev.inactive + 1 : prev.inactive - 1,
        }));
      }
    } catch (error) {
      console.error("Error toggling skill:", error);
    }
  };

  const triggerSync = async () => {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res = await fetch("/api/admin/knowledge/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: true }),
      });
      const data = await res.json();
      if (data.success) {
        setSyncMessage(data.message);
        await fetchSkills();
      } else {
        setSyncMessage(`Error: ${data.error}`);
      }
    } catch (error) {
      setSyncMessage("Error de conexión durante sincronización");
      console.error("Error syncing:", error);
    } finally {
      setSyncing(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <StatCard label="Total Skills" value={stats.total} color="text-white" />
        <StatCard label="Activos" value={stats.active} color="text-green-400" />
        <StatCard label="Inactivos" value={stats.inactive} color="text-slate-400" />
        <StatCard label="CWE Mappings" value={stats.cweMappings} color="text-cyan-400" />
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm">Última Sync</div>
          <div className="text-sm font-semibold text-purple-400 mt-1">
            {stats.lastSync ? new Date(stats.lastSync).toLocaleDateString("es-ES", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "Nunca"}
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex-1 min-w-[200px] relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
            placeholder="Buscar skills..."
            className="w-full bg-slate-800 text-white pl-10 pr-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
          />
        </div>
        <select
          value={selectedCategory}
          onChange={(e) => { setSelectedCategory(e.target.value); setPage(1); }}
          className="bg-slate-800 text-white px-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
        >
          <option value="all">Todas las categorías</option>
          {categories.map((c) => (
            <option key={c.category} value={c.category}>
              {c.category} ({c.count})
            </option>
          ))}
        </select>
        <button
          onClick={triggerSync}
          disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-600 text-white rounded-lg transition-colors font-medium"
        >
          <RefreshCw className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`} />
          {syncing ? "Sincronizando..." : "Re-sincronizar desde GitHub"}
        </button>
      </div>

      {/* Sync message */}
      {syncMessage && (
        <div className={`px-4 py-3 rounded-lg border text-sm ${syncMessage.startsWith("Error") ? "bg-red-500/10 border-red-500/30 text-red-400" : "bg-green-500/10 border-green-500/30 text-green-400"}`}>
          {syncMessage}
        </div>
      )}

      {/* Skills table */}
      <div className="border border-slate-700 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800/80 border-b border-slate-700">
              <th className="text-left px-4 py-3 text-slate-400 font-medium w-8"></th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Skill</th>
              <th className="text-left px-4 py-3 text-slate-400 font-medium">Categoría</th>
              <th className="text-center px-4 py-3 text-slate-400 font-medium">CWEs</th>
              <th className="text-center px-4 py-3 text-slate-400 font-medium">Reports</th>
              <th className="text-center px-4 py-3 text-slate-400 font-medium">Estado</th>
              <th className="text-center px-4 py-3 text-slate-400 font-medium w-16">Acción</th>
            </tr>
          </thead>
          <tbody>
            {skills.map((skill) => (
              <SkillRow
                key={skill.id}
                skill={skill}
                expanded={expandedId === skill.id}
                onToggleExpand={() => setExpandedId(expandedId === skill.id ? null : skill.id)}
                onToggleActive={() => toggleActive(skill.id, skill.isActive)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {skills.length === 0 && (
        <div className="text-center py-12 text-slate-400">
          No se encontraron skills. Ejecuta la sincronización para cargar desde GitHub.
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-300 disabled:opacity-40 hover:bg-slate-700 transition-colors"
          >
            Anterior
          </button>
          <span className="text-slate-400 text-sm px-3">
            Página {page} de {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-300 disabled:opacity-40 hover:bg-slate-700 transition-colors"
          >
            Siguiente
          </button>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
      <div className="text-slate-400 text-sm">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function SkillRow({
  skill,
  expanded,
  onToggleExpand,
  onToggleActive,
}: {
  skill: HuntSkillData;
  expanded: boolean;
  onToggleExpand: () => void;
  onToggleActive: () => void;
}) {
  return (
    <>
      <tr
        className={`border-b border-slate-700/50 hover:bg-slate-800/50 cursor-pointer transition-colors ${!skill.isActive ? "opacity-50" : ""}`}
        onClick={onToggleExpand}
      >
        <td className="px-4 py-3">
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
        </td>
        <td className="px-4 py-3">
          <div className="font-medium text-white">{skill.name}</div>
          <div className="text-xs text-slate-500 font-mono">{skill.slug}</div>
        </td>
        <td className="px-4 py-3">
          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
            {skill.category}
          </span>
        </td>
        <td className="px-4 py-3 text-center text-cyan-400 font-medium">
          {skill.cweMappings?.length || 0}
        </td>
        <td className="px-4 py-3 text-center text-slate-300">{skill.reportCount}</td>
        <td className="px-4 py-3 text-center">
          <span className={`px-2 py-1 text-xs rounded ${skill.isActive ? "bg-green-500/20 text-green-400" : "bg-slate-700 text-slate-400"}`}>
            {skill.isActive ? "Activo" : "Inactivo"}
          </span>
        </td>
        <td className="px-4 py-3 text-center">
          <button
            onClick={(e) => { e.stopPropagation(); onToggleActive(); }}
            className={`p-1.5 rounded transition-colors ${skill.isActive ? "text-green-400 hover:bg-green-500/20" : "text-slate-400 hover:bg-slate-700"}`}
            title={skill.isActive ? "Desactivar" : "Activar"}
          >
            {skill.isActive ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
          </button>
        </td>
      </tr>

      {expanded && (
        <tr className="bg-slate-900/50">
          <td colSpan={7} className="px-6 py-4">
            <SkillDetail skill={skill} />
          </td>
        </tr>
      )}
    </>
  );
}

function SkillDetail({ skill }: { skill: HuntSkillData }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-sm">
      {/* Description */}
      <div className="lg:col-span-2">
        <p className="text-slate-300">{skill.description}</p>
        <div className="flex flex-wrap gap-2 mt-2">
          {skill.languages.map((l) => (
            <span key={l} className="px-2 py-0.5 bg-blue-500/10 text-blue-400 text-xs rounded">{l}</span>
          ))}
          {skill.frameworks.map((f) => (
            <span key={f} className="px-2 py-0.5 bg-indigo-500/10 text-indigo-400 text-xs rounded">{f}</span>
          ))}
        </div>
      </div>

      {/* CWE Mappings */}
      {skill.cweMappings.length > 0 && (
        <Section icon={<Link2 className="w-4 h-4 text-cyan-400" />} title="CWE Mappings">
          <div className="flex flex-wrap gap-2">
            {skill.cweMappings.map((m) => (
              <a
                key={m.id}
                href={`https://cwe.mitre.org/data/definitions/${m.cweId.replace("CWE-", "")}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2 py-1 bg-cyan-500/10 text-cyan-400 text-xs rounded hover:bg-cyan-500/20 transition-colors"
              >
                {m.cweId} <span className="text-cyan-600">({m.relevance})</span>
              </a>
            ))}
          </div>
        </Section>
      )}

      {/* Root Causes */}
      {skill.rootCauses && skill.rootCauses.length > 0 && (
        <Section icon={<AlertTriangle className="w-4 h-4 text-amber-400" />} title="Causas Raíz">
          <ol className="list-decimal list-inside space-y-1">
            {skill.rootCauses.map((rc, i) => (
              <li key={i} className="text-slate-300">
                <span className="font-medium text-white">{rc.title}</span>
                {rc.detail && <span className="text-slate-400"> — {rc.detail}</span>}
              </li>
            ))}
          </ol>
        </Section>
      )}

      {/* Validation Gate */}
      {skill.validationGate && skill.validationGate.length > 0 && (
        <Section icon={<Shield className="w-4 h-4 text-green-400" />} title="Validation Gate">
          <div className="space-y-2">
            {skill.validationGate.map((v, i) => (
              <div key={i} className="bg-slate-800/50 rounded p-2">
                <p className="text-white font-medium">{v.question}</p>
                <p className="text-slate-400 text-xs mt-0.5">{v.criteria}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Detection Patterns */}
      {skill.detectionPatterns && skill.detectionPatterns.length > 0 && (
        <Section icon={<Brain className="w-4 h-4 text-purple-400" />} title="Detection Patterns">
          <div className="space-y-2">
            {skill.detectionPatterns.slice(0, 5).map((dp, i) => (
              <div key={i} className="bg-slate-800/50 rounded p-2">
                <p className="text-white text-xs font-medium">{dp.name} <span className="text-slate-500">({dp.language})</span></p>
                <code className="text-xs text-cyan-300 block mt-1 truncate">{dp.pattern}</code>
              </div>
            ))}
            {skill.detectionPatterns.length > 5 && (
              <p className="text-slate-500 text-xs">+{skill.detectionPatterns.length - 5} más...</p>
            )}
          </div>
        </Section>
      )}

      {/* Impact Examples */}
      {skill.impactExamples && skill.impactExamples.length > 0 && (
        <Section icon={<AlertTriangle className="w-4 h-4 text-red-400" />} title="Impacto Real">
          <div className="space-y-2">
            {skill.impactExamples.slice(0, 3).map((ex, i) => (
              <div key={i} className="bg-slate-800/50 rounded p-2">
                <p className="text-white text-xs font-medium">{ex.scenario}</p>
                <p className="text-slate-400 text-xs mt-0.5">{ex.description}</p>
                {ex.cveIds.length > 0 && (
                  <div className="flex gap-1 mt-1">
                    {ex.cveIds.map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-red-400 hover:text-red-300 underline"
                      >
                        {cve}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Chains */}
      {skill.chains && skill.chains.length > 0 && (
        <Section icon={<Link2 className="w-4 h-4 text-orange-400" />} title="Cadenas de Ataque">
          <div className="space-y-1">
            {skill.chains.map((chain, i) => (
              <div key={i} className="text-slate-300 text-xs">
                → <span className="text-orange-400 font-medium">{chain.targetSkill}</span>: {chain.primitive}
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <h4 className="text-slate-200 font-semibold">{title}</h4>
      </div>
      {children}
    </div>
  );
}

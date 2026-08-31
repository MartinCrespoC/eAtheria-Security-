"use client";

import { useState, useEffect } from "react";
import { Search, Plus, Edit2, Trash2, Power, PowerOff, Code2, X } from "lucide-react";

const EMPTY_FORM = {
  language: "javascript",
  pattern: "",
  description: "",
  reason: "",
  context: "",
  cweIds: "",
  examples: "",
};

interface FalsePositivePattern {
  id: string;
  language: string;
  pattern: string;
  description: string;
  reason: string;
  context?: string;
  cweIds: string[];
  examples: string[];
  isActive: boolean;
  createdAt: string;
  // FP Knowledge System provenance
  source?: string; // builtin | gitleaks | cwe | semgrep | juliet | manual
  confidence?: number; // 0-100
  category?: string | null;
  sourceRuleId?: string | null;
}

const SOURCE_STYLES: Record<string, string> = {
  builtin: "bg-blue-500/20 text-blue-400",
  gitleaks: "bg-amber-500/20 text-amber-400",
  cwe: "bg-violet-500/20 text-violet-400",
  semgrep: "bg-pink-500/20 text-pink-400",
  juliet: "bg-teal-500/20 text-teal-400",
  manual: "bg-orange-500/20 text-orange-400",
};

export function FalsePositiveManager() {
  const [patterns, setPatterns] = useState<FalsePositivePattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedLanguage, setSelectedLanguage] = useState<string>("all");
  const [selectedSource, setSelectedSource] = useState<string>("all");
  const [showModal, setShowModal] = useState(false);
  const [editingPattern, setEditingPattern] = useState<FalsePositivePattern | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  const [stats, setStats] = useState({
    total: 0,
    active: 0,
    inactive: 0,
    byLanguage: {} as Record<string, number>,
    bySource: {} as Record<string, number>,
  });

  useEffect(() => {
    fetchPatterns();
  }, [selectedLanguage, selectedSource]);

  const fetchPatterns = async () => {
    try {
      const params = new URLSearchParams();
      if (selectedLanguage !== "all") params.set("language", selectedLanguage);
      if (selectedSource !== "all") params.set("source", selectedSource);
      const qs = params.toString();
      const url = qs ? `/api/admin/false-positives?${qs}` : "/api/admin/false-positives";

      const res = await fetch(url);
      const data = await res.json();

      if (data.success) {
        setPatterns(data.patterns);
        setStats({ bySource: {}, byLanguage: {}, ...data.stats });
      }
    } catch (error) {
      console.error("Error fetching patterns:", error);
    } finally {
      setLoading(false);
    }
  };

  const toggleActive = async (id: string, currentState: boolean) => {
    try {
      const res = await fetch(`/api/admin/false-positives/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isActive: !currentState }),
      });

      if (res.ok) {
        await fetchPatterns();
      }
    } catch (error) {
      console.error("Error toggling pattern:", error);
    }
  };

  const deletePattern = async (id: string) => {
    if (!confirm("¿Eliminar este patrón?")) return;

    try {
      const res = await fetch(`/api/admin/false-positives/${id}`, {
        method: "DELETE",
      });

      if (res.ok) {
        await fetchPatterns();
      }
    } catch (error) {
      console.error("Error deleting pattern:", error);
    }
  };

  const openCreate = () => {
    setEditingPattern(null);
    setForm(EMPTY_FORM);
    setFormError("");
    setShowModal(true);
  };

  const openEdit = (p: FalsePositivePattern) => {
    setEditingPattern(p);
    setForm({
      language: p.language,
      pattern: p.pattern,
      description: p.description,
      reason: p.reason,
      context: p.context || "",
      cweIds: p.cweIds.join(", "),
      examples: p.examples.join("\n"),
    });
    setFormError("");
    setShowModal(true);
  };

  const savePattern = async () => {
    setFormError("");
    if (!form.pattern.trim() || !form.description.trim() || !form.reason.trim()) {
      setFormError("Patrón, descripción y razón son obligatorios");
      return;
    }
    const payload = {
      language: form.language.trim(),
      pattern: form.pattern.trim(),
      description: form.description.trim(),
      reason: form.reason.trim(),
      context: form.context.trim() || undefined,
      cweIds: form.cweIds.split(",").map((s) => s.trim()).filter(Boolean),
      examples: form.examples.split("\n").map((s) => s.trim()).filter(Boolean),
    };
    setSaving(true);
    try {
      const res = await fetch(
        editingPattern
          ? `/api/admin/false-positives/${editingPattern.id}`
          : "/api/admin/false-positives",
        {
          method: editingPattern ? "PATCH" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );
      const data = await res.json();
      if (data.success) {
        setShowModal(false);
        await fetchPatterns();
      } else {
        setFormError(data.error || "Error al guardar");
      }
    } catch {
      setFormError("Error de red al guardar");
    } finally {
      setSaving(false);
    }
  };

  const filteredPatterns = patterns.filter(
    (p) =>
      p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.pattern.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.language.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.source || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.category || "").toLowerCase().includes(searchTerm.toLowerCase())
  );

  const languages = Object.keys(stats.byLanguage).sort();
  const sources = Object.keys(stats.bySource).sort();

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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm">Total Patrones</div>
          <div className="text-2xl font-bold text-white">{stats.total}</div>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm">Activos</div>
          <div className="text-2xl font-bold text-green-400">{stats.active}</div>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm">Inactivos</div>
          <div className="text-2xl font-bold text-slate-400">{stats.inactive}</div>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <div className="text-slate-400 text-sm">Lenguajes</div>
          <div className="text-2xl font-bold text-cyan-400">{languages.length}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar patrones..."
            className="w-full bg-slate-800 text-white pl-10 pr-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
          />
        </div>
        <select
          value={selectedLanguage}
          onChange={(e) => setSelectedLanguage(e.target.value)}
          className="bg-slate-800 text-white px-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
        >
          <option value="all">Todos los lenguajes</option>
          {languages.map((lang) => (
            <option key={lang} value={lang}>
              {lang} ({stats.byLanguage[lang]})
            </option>
          ))}
        </select>
        <select
          value={selectedSource}
          onChange={(e) => setSelectedSource(e.target.value)}
          className="bg-slate-800 text-white px-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
          title="Filtrar por fuente de conocimiento"
        >
          <option value="all">Todas las fuentes</option>
          {sources.map((src) => (
            <option key={src} value={src}>
              {src} ({stats.bySource[src]})
            </option>
          ))}
        </select>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Nuevo Patrón
        </button>
      </div>

      {/* Patterns List */}
      <div className="space-y-3">
        {filteredPatterns.map((pattern) => (
          <div
            key={pattern.id}
            className="bg-slate-800 p-4 rounded-lg border border-slate-700 hover:border-cyan-400 transition-colors"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded font-mono">
                    {pattern.language}
                  </span>
                  <span
                    className={`px-2 py-1 text-xs rounded font-mono ${SOURCE_STYLES[pattern.source || "manual"] || "bg-slate-700 text-slate-300"}`}
                    title={pattern.sourceRuleId ? `Rule: ${pattern.sourceRuleId}` : `Fuente: ${pattern.source || "manual"}`}
                  >
                    {pattern.source || "manual"}
                    {typeof pattern.confidence === "number" ? ` · ${pattern.confidence}%` : ""}
                  </span>
                  {pattern.context && (
                    <span className="px-2 py-1 bg-slate-700 text-slate-300 text-xs rounded">
                      {pattern.context}
                    </span>
                  )}
                  <span className={`px-2 py-1 text-xs rounded ${
                    pattern.isActive
                      ? "bg-green-500/20 text-green-400"
                      : "bg-slate-700 text-slate-400"
                  }`}>
                    {pattern.isActive ? "Activo" : "Inactivo"}
                  </span>
                </div>
                <h3 className="text-white font-semibold mb-1">{pattern.description}</h3>
                <p className="text-slate-400 text-sm mb-2">{pattern.reason}</p>
                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <Code2 className="w-3 h-3" />
                  <code className="bg-slate-900 px-2 py-1 rounded">{pattern.pattern}</code>
                </div>
                {pattern.cweIds.length > 0 && (
                  <div className="mt-2 flex gap-1">
                    {pattern.cweIds.map((cwe) => (
                      <span key={cwe} className="px-2 py-1 bg-cyan-500/10 text-cyan-400 text-xs rounded">
                        {cwe}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <div className="flex gap-2 ml-4">
                <button
                  onClick={() => openEdit(pattern)}
                  className="p-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
                  title="Editar"
                >
                  <Edit2 className="w-4 h-4" />
                </button>
                <button
                  onClick={() => toggleActive(pattern.id, pattern.isActive)}
                  className={`p-2 rounded-lg transition-colors ${
                    pattern.isActive
                      ? "bg-green-500/20 text-green-400 hover:bg-green-500/30"
                      : "bg-slate-700 text-slate-400 hover:bg-slate-600"
                  }`}
                  title={pattern.isActive ? "Desactivar" : "Activar"}
                >
                  {pattern.isActive ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => deletePattern(pattern.id)}
                  className="p-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors"
                  title="Eliminar"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredPatterns.length === 0 && (
        <div className="text-center py-12 text-slate-400">
          No se encontraron patrones
        </div>
      )}

      {/* Create / Edit modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-slate-800 rounded-lg border border-slate-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">
                {editingPattern ? "Editar Patrón" : "Nuevo Patrón"}
              </h2>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-500/20 text-red-400 rounded-lg text-sm">{formError}</div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Lenguaje</label>
                <select
                  value={form.language}
                  onChange={(e) => setForm({ ...form, language: e.target.value })}
                  className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
                >
                  {["javascript", "typescript", "python", "java", "csharp", "php", "ruby", "go", "rust", "kotlin", "swift", "scala", "sap", "generic"].map((l) => (
                    <option key={l} value={l}>{l}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Contexto (opcional)</label>
                <input
                  value={form.context}
                  onChange={(e) => setForm({ ...form, context: e.target.value })}
                  placeholder="dev, test, prod..."
                  className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm text-slate-400 mb-1">Patrón (regex o fragmento de código)</label>
              <input
                value={form.pattern}
                onChange={(e) => setForm({ ...form, pattern: e.target.value })}
                placeholder="console\\.log\\("
                className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm text-slate-400 mb-1">Descripción</label>
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Qué detecta este patrón de falso positivo"
                className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm text-slate-400 mb-1">Razón (por qué es falso positivo)</label>
              <textarea
                value={form.reason}
                onChange={(e) => setForm({ ...form, reason: e.target.value })}
                rows={2}
                className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm text-slate-400 mb-1">CWE IDs (separados por coma)</label>
              <input
                value={form.cweIds}
                onChange={(e) => setForm({ ...form, cweIds: e.target.value })}
                placeholder="CWE-79, CWE-89"
                className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm text-slate-400 mb-1">Ejemplos (uno por línea)</label>
              <textarea
                value={form.examples}
                onChange={(e) => setForm({ ...form, examples: e.target.value })}
                rows={3}
                className="w-full bg-slate-900 text-white px-3 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none font-mono text-sm"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
              >
                Cancelar
              </button>
              <button
                onClick={savePattern}
                disabled={saving}
                className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
              >
                {saving ? "Guardando..." : editingPattern ? "Guardar Cambios" : "Crear Patrón"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

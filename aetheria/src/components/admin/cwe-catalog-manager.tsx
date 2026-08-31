"use client";

import { useState, useEffect } from "react";
import { RefreshCw, Shield, TrendingUp, Calendar, ExternalLink, Download, CheckCircle2, AlertCircle } from "lucide-react";

interface CWE {
  id: string;
  name: string;
  rank: number;
  year: number;
  score: number;
}

export function CWECatalogManager() {
  const [cwes, setCwes] = useState<CWE[]>([]);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [availableYears, setAvailableYears] = useState<{year: number; status: string; count: number}[]>([]);
  const [showYearSelector, setShowYearSelector] = useState(false);

  useEffect(() => {
    fetchCatalog();
  }, []);

  useEffect(() => {
    if (cwes.length > 0) {
      checkAvailableYears();
    }
  }, [cwes]);

  const fetchCatalog = async () => {
    try {
      const res = await fetch("/api/admin/cwe-catalog");
      const data = await res.json();
      if (data.success) {
        setCwes(data.catalog.cwes || []);
        setLastUpdated(data.catalog.lastUpdated);
      }
    } catch (error) {
      console.error("Error fetching catalog:", error);
    } finally {
      setLoading(false);
    }
  };

  const checkAvailableYears = async () => {
    try {
      const currentYear = new Date().getFullYear();
      const years = [];

      // Check current year and previous 3 years
      for (let year = currentYear; year >= currentYear - 3; year--) {
        const existingCount = cwes.filter(c => c.year === year).length;
        years.push({
          year,
          status: existingCount > 0 ? 'synced' : 'available',
          count: existingCount
        });
      }

      setAvailableYears(years);
    } catch (error) {
      console.error('Error checking years:', error);
    }
  };

  const updateCatalog = async (year?: number) => {
    setUpdating(true);
    try {
      const res = await fetch("/api/admin/cwe-catalog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "update", year }),
      });
      const data = await res.json();
      if (data.success) {
        setMessage({ type: "success", text: `✅ Catálogo actualizado: ${data.count} CWEs${year ? ` del ${year}` : ''}` });
        await fetchCatalog();
        await checkAvailableYears();
        setShowYearSelector(false);
      } else {
        setMessage({ type: "error", text: data.error || "❌ Error al actualizar" });
      }
    } catch (error) {
      setMessage({ type: "error", text: "❌ Error de conexión" });
    } finally {
      setUpdating(false);
      setTimeout(() => setMessage(null), 4000);
    }
  };

  const filteredCwes = cwes.filter(
    (cwe) =>
      cwe.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cwe.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const stats = {
    total: cwes.length,
    top10: cwes.filter((c) => c.rank <= 10).length,
    top25: cwes.filter((c) => c.rank <= 25).length,
    top50: cwes.filter((c) => c.rank <= 50).length,
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
      {/* Header Actions */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex-1">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar CWE por ID o nombre..."
            className="w-full bg-slate-800 text-white px-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none"
          />
        </div>
        <div className="relative">
          <button
            onClick={() => setShowYearSelector(!showYearSelector)}
            disabled={updating}
            className="bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-600 text-white px-6 py-2 rounded-lg font-semibold flex items-center gap-2 transition-colors"
          >
            <Download className={`w-5 h-5 ${updating ? "animate-bounce" : ""}`} />
            {updating ? "Sincronizando..." : "Sincronizar CWE"}
          </button>

          {/* Year Selector Dropdown */}
          {showYearSelector && !updating && (
            <div className="absolute right-0 mt-2 w-80 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-10 p-4">
              <div className="mb-3">
                <h3 className="text-white font-semibold text-sm mb-1">Sincronizar CWE Top 25</h3>
                <p className="text-slate-400 text-xs">Selecciona el año para sincronizar desde MITRE</p>
              </div>

              <div className="space-y-2">
                {availableYears.map((yearData) => (
                  <button
                    key={yearData.year}
                    onClick={() => updateCatalog(yearData.year)}
                    className="w-full flex items-center justify-between p-3 rounded-lg bg-slate-900 hover:bg-slate-700 border border-slate-700 hover:border-cyan-500 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Calendar className="w-4 h-4 text-cyan-400" />
                      <div className="text-left">
                        <div className="text-white font-medium text-sm">CWE Top 25 {yearData.year}</div>
                        <div className="text-slate-400 text-xs">
                          {yearData.status === 'synced' ? `${yearData.count} CWEs sincronizados` : 'No sincronizado'}
                        </div>
                      </div>
                    </div>
                    {yearData.status === 'synced' ? (
                      <CheckCircle2 className="w-5 h-5 text-green-400" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-yellow-400" />
                    )}
                  </button>
                ))}
              </div>

              <div className="mt-3 pt-3 border-t border-slate-700">
                <button
                  onClick={() => updateCatalog()}
                  className="w-full p-2 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 text-purple-400 text-sm font-medium transition-colors"
                >
                  <RefreshCw className="w-4 h-4 inline mr-2" />
                  Sincronizar todos los años
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Message */}
      {message && (
        <div
          className={`p-4 rounded-lg border ${
            message.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="text-slate-400 text-sm">Total CWEs</span>
          </div>
          <div className="text-3xl font-bold text-white">{stats.total}</div>
        </div>
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp className="w-5 h-5 text-red-400" />
            <span className="text-slate-400 text-sm">Top 10</span>
          </div>
          <div className="text-3xl font-bold text-white">{stats.top10}</div>
        </div>
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp className="w-5 h-5 text-orange-400" />
            <span className="text-slate-400 text-sm">Top 25</span>
          </div>
          <div className="text-3xl font-bold text-white">{stats.top25}</div>
        </div>
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <div className="flex items-center gap-3 mb-2">
            <TrendingUp className="w-5 h-5 text-yellow-400" />
            <span className="text-slate-400 text-sm">Top 50</span>
          </div>
          <div className="text-3xl font-bold text-white">{stats.top50}</div>
        </div>
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <div className="flex items-center gap-3 mb-2">
            <Calendar className="w-5 h-5 text-purple-400" />
            <span className="text-slate-400 text-sm">Última Act.</span>
          </div>
          <div className="text-sm font-semibold text-white">
            {lastUpdated ? new Date(lastUpdated).toLocaleDateString() : "Nunca"}
          </div>
        </div>
      </div>

      {/* CWE Table */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-900 border-b border-slate-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Rank
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  CWE ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Nombre
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Año
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Acción
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {filteredCwes.map((cwe) => (
                <tr key={cwe.id} className="hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center justify-center w-10 h-10 rounded-full font-bold text-sm ${
                        cwe.rank <= 10
                          ? "bg-red-500/20 text-red-400"
                          : cwe.rank <= 25
                          ? "bg-orange-500/20 text-orange-400"
                          : cwe.rank <= 50
                          ? "bg-yellow-500/20 text-yellow-400"
                          : "bg-slate-700 text-slate-400"
                      }`}
                    >
                      #{cwe.rank}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-cyan-400 font-mono font-semibold">{cwe.id}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-white font-medium">{cwe.name}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-slate-300 font-mono">{cwe.score.toFixed(2)}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="text-slate-400">{cwe.year}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${cwe.id.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-sm"
                    >
                      Ver en MITRE
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filteredCwes.length === 0 && (
        <div className="text-center py-12 text-slate-400">
          No se encontraron CWEs que coincidan con tu búsqueda
        </div>
      )}
    </div>
  );
}

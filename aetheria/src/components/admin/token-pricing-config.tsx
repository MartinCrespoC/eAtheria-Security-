"use client";

import { useState } from "react";
import { Save, Loader2, DollarSign } from "lucide-react";

interface CompanyPricing {
  id: string;
  name: string;
  slug: string;
  customInputTokenCost: number | null;
  customOutputTokenCost: number | null;
  aiTokenLimit: number | null;
  aiCostLimit: number | null;
}

export function TokenPricingConfig({ companies }: { companies: CompanyPricing[] }) {
  const [saving, setSaving] = useState<string | null>(null);
  const [rows, setRows] = useState(
    companies.map((c) => ({
      ...c,
      inputCost: c.customInputTokenCost?.toString() || "",
      outputCost: c.customOutputTokenCost?.toString() || "",
    }))
  );

  const handleSave = async (companyId: string, inputCost: string, outputCost: string) => {
    setSaving(companyId);
    try {
      const res = await fetch("/api/admin/analytics/costs", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          companyId,
          customInputTokenCost: inputCost ? parseFloat(inputCost) : null,
          customOutputTokenCost: outputCost ? parseFloat(outputCost) : null,
        }),
      });
      if (!res.ok) throw new Error("Failed");
      setRows((prev) =>
        prev.map((r) =>
          r.id === companyId
            ? { ...r, customInputTokenCost: inputCost ? parseFloat(inputCost) : null, customOutputTokenCost: outputCost ? parseFloat(outputCost) : null }
            : r
        )
      );
    } catch {
      // silent
    } finally {
      setSaving(null);
    }
  };

  if (companies.length === 0) {
    return (
      <p className="text-slate-500 text-center py-8">No hay empresas registradas</p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-slate-800/60">
            <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 uppercase">Empresa</th>
            <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 uppercase">Costo/1M Input ($)</th>
            <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 uppercase">Costo/1M Output ($)</th>
            <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 uppercase">Límite Tokens/Mes</th>
            <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 uppercase">Límite Costo/Mes ($)</th>
            <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 uppercase">Acción</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className="border-b border-slate-800/30 hover:bg-slate-800/20">
              <td className="px-4 py-3">
                <p className="text-sm font-medium text-white">{row.name}</p>
                <p className="text-xs text-slate-500 font-mono">{row.slug}</p>
              </td>
              <td className="px-4 py-3 text-right">
                <input
                  type="number"
                  step="0.001"
                  value={row.inputCost}
                  onChange={(e) => setRows((prev) => prev.map((r) => r.id === row.id ? { ...r, inputCost: e.target.value } : r))}
                  placeholder="Default"
                  className="w-24 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm text-right placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                />
              </td>
              <td className="px-4 py-3 text-right">
                <input
                  type="number"
                  step="0.001"
                  value={row.outputCost}
                  onChange={(e) => setRows((prev) => prev.map((r) => r.id === row.id ? { ...r, outputCost: e.target.value } : r))}
                  placeholder="Default"
                  className="w-24 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm text-right placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
                />
              </td>
              <td className="px-4 py-3 text-right text-sm text-slate-400">
                {row.aiTokenLimit ? row.aiTokenLimit.toLocaleString() : "Ilimitado"}
              </td>
              <td className="px-4 py-3 text-right text-sm text-slate-400">
                {row.aiCostLimit ? `$${row.aiCostLimit}` : "Ilimitado"}
              </td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => handleSave(row.id, row.inputCost, row.outputCost)}
                  disabled={saving === row.id}
                  className="inline-flex items-center gap-1 px-3 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                >
                  {saving === row.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
                  Guardar
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-xs text-slate-500 mt-3 flex items-center gap-1">
        <DollarSign className="h-3 w-3" />
        Costo por 1M tokens. Si se deja vacío, se usa el costo del modelo configurado en AI Models.
      </p>
    </div>
  );
}

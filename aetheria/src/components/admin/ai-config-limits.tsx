"use client";

import { useEffect, useState, useCallback } from "react";
import { Loader2, Save, Gauge, AlertTriangle } from "lucide-react";

interface ProviderLimit {
  id: string;
  name: string;
  slug: string;
  isActive: boolean;
  maxTokensPerMonth: number | null;
  costLimitPerMonth: string | null;
}

interface CompanyLimit {
  id: string;
  name: string;
  slug: string;
  aiTokenLimit: number | null;
  aiCostLimit: string | null;
  aiProvider: { id: string; name: string } | null;
}

export function AIConfigLimits() {
  const [providers, setProviders] = useState<ProviderLimit[]>([]);
  const [companies, setCompanies] = useState<CompanyLimit[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const showMsg = useCallback((type: "success" | "error", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/ai-configuration/limits");
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers || []);
        setCompanies(data.companies || []);
      }
    } catch {
      showMsg("error", "Failed to load limits");
    } finally {
      setLoading(false);
    }
  }, [showMsg]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  async function saveProviderLimit(provider: ProviderLimit, tokens: string, cost: string) {
    setSaving(`provider-${provider.id}`);
    try {
      const res = await fetch("/api/admin/ai-configuration/limits", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "provider",
          id: provider.id,
          maxTokensPerMonth: tokens ? parseInt(tokens) : null,
          costLimit: cost ? parseFloat(cost) : null,
        }),
      });
      if (res.ok) {
        showMsg("success", `Limits updated for ${provider.name}`);
        await fetchData();
      }
    } catch {
      showMsg("error", "Failed to save");
    }
    setSaving(null);
  }

  async function saveCompanyLimit(company: CompanyLimit, tokens: string, cost: string) {
    setSaving(`company-${company.id}`);
    try {
      const res = await fetch("/api/admin/ai-configuration/limits", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "company",
          id: company.id,
          maxTokensPerMonth: tokens ? parseInt(tokens) : null,
          costLimit: cost ? parseFloat(cost) : null,
        }),
      });
      if (res.ok) {
        showMsg("success", `Limits updated for ${company.name}`);
        await fetchData();
      }
    } catch {
      showMsg("error", "Failed to save");
    }
    setSaving(null);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {message && (
        <div
          className={`rounded-lg px-4 py-3 text-sm font-medium ${
            message.type === "success"
              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border border-red-500/30 text-red-400"
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Alert thresholds info */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-amber-400">Alert Thresholds</p>
          <p className="text-xs text-slate-400 mt-1">
            Companies receive a warning notification at 80% usage. AI features are blocked at 100%.
            Leave fields empty for unlimited usage.
          </p>
        </div>
      </div>

      {/* Provider Limits */}
      <div>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
          <Gauge className="h-5 w-5 text-cyan-400" />
          Provider Limits
        </h2>
        <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/60 bg-slate-900/60">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Provider</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Max Tokens / Month</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Cost Limit (USD)</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {providers.map((p) => (
                  <ProviderLimitRow
                    key={p.id}
                    provider={p}
                    saving={saving === `provider-${p.id}`}
                    onSave={saveProviderLimit}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Company Limits */}
      <div>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
          <Gauge className="h-5 w-5 text-purple-400" />
          Company Limits
        </h2>
        <div className="rounded-xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/60 bg-slate-900/60">
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Company</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Provider</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Max Tokens / Month</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Cost Limit (USD)</th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {companies.map((c) => (
                  <CompanyLimitRow
                    key={c.id}
                    company={c}
                    saving={saving === `company-${c.id}`}
                    onSave={saveCompanyLimit}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {providers.length === 0 && companies.length === 0 && (
        <div className="text-center py-12">
          <Gauge className="h-10 w-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400">No limits configured.</p>
        </div>
      )}
    </div>
  );
}

function ProviderLimitRow({
  provider,
  saving,
  onSave,
}: {
  provider: ProviderLimit;
  saving: boolean;
  onSave: (p: ProviderLimit, tokens: string, cost: string) => void;
}) {
  const [tokens, setTokens] = useState(provider.maxTokensPerMonth?.toString() || "");
  const [cost, setCost] = useState(provider.costLimitPerMonth || "");

  return (
    <tr className="hover:bg-slate-800/20 transition-colors">
      <td className="px-4 py-3">
        <p className="text-sm font-medium text-white">{provider.name}</p>
        <p className="text-xs text-slate-500 font-mono">{provider.slug}</p>
      </td>
      <td className="px-4 py-3">
        <input
          type="number"
          value={tokens}
          onChange={(e) => setTokens(e.target.value)}
          placeholder="Unlimited"
          className="w-32 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="number"
          step="0.01"
          value={cost}
          onChange={(e) => setCost(e.target.value)}
          placeholder="Unlimited"
          className="w-32 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
        />
      </td>
      <td className="px-4 py-3 text-right">
        <button
          onClick={() => onSave(provider, tokens, cost)}
          disabled={saving}
          className="inline-flex items-center gap-1 px-3 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
          Save
        </button>
      </td>
    </tr>
  );
}

function CompanyLimitRow({
  company,
  saving,
  onSave,
}: {
  company: CompanyLimit;
  saving: boolean;
  onSave: (c: CompanyLimit, tokens: string, cost: string) => void;
}) {
  const [tokens, setTokens] = useState(company.aiTokenLimit?.toString() || "");
  const [cost, setCost] = useState(company.aiCostLimit || "");

  return (
    <tr className="hover:bg-slate-800/20 transition-colors">
      <td className="px-4 py-3">
        <p className="text-sm font-medium text-white">{company.name}</p>
        <p className="text-xs text-slate-500 font-mono">{company.slug}</p>
      </td>
      <td className="px-4 py-3 text-sm text-slate-300">
        {company.aiProvider?.name || "—"}
      </td>
      <td className="px-4 py-3">
        <input
          type="number"
          value={tokens}
          onChange={(e) => setTokens(e.target.value)}
          placeholder="Unlimited"
          className="w-32 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="number"
          step="0.01"
          value={cost}
          onChange={(e) => setCost(e.target.value)}
          placeholder="Unlimited"
          className="w-32 px-2 py-1 rounded-md bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:border-cyan-500/50 focus:outline-none"
        />
      </td>
      <td className="px-4 py-3 text-right">
        <button
          onClick={() => onSave(company, tokens, cost)}
          disabled={saving}
          className="inline-flex items-center gap-1 px-3 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
          Save
        </button>
      </td>
    </tr>
  );
}

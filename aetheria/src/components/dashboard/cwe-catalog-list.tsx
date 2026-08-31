"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Search, BookOpen, ExternalLink } from "lucide-react";

interface CweData {
  id: string;
  cweId: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  remediation: string | null;
}

const SEV_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "default"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "default",
};

export function CweCatalogList({ catalog }: { catalog: CweData[] }) {
  const [search, setSearch] = useState("");

  const filtered = catalog.filter((c) => {
    const q = search.toLowerCase();
    return (
      c.cweId.toLowerCase().includes(q) ||
      c.name.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
        <input
          type="text"
          placeholder="Buscar CWE..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-10 w-full rounded-lg border border-border bg-card pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
        />
      </div>

      <p className="text-sm text-text-muted">{filtered.length} entradas</p>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-text-muted">
          <BookOpen className="h-10 w-10 mb-3 opacity-40" />
          <p>Sin resultados</p>
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">CWE</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">Nombre</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-text-muted uppercase">Categoría</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-text-muted uppercase">Severidad</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-text-muted uppercase">Ref</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.id} className="border-b border-border hover:bg-surface transition-colors">
                  <td className="px-4 py-3 text-sm font-mono text-accent">{c.cweId}</td>
                  <td className="px-4 py-3">
                    <p className="text-sm text-text-primary">{c.name}</p>
                    <p className="text-xs text-text-muted mt-0.5 line-clamp-1">{c.description}</p>
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">{c.category}</td>
                  <td className="px-4 py-3 text-center">
                    <Badge variant={SEV_VARIANT[c.severity] ?? "default"}>{c.severity}</Badge>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${c.cweId.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-text-muted hover:text-accent transition-colors"
                    >
                      <ExternalLink className="h-4 w-4 inline" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

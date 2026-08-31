"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BarChart3, Eye, Globe, Monitor } from "lucide-react";

interface AnalyticsData {
  totalEvents: number;
  eventsByType: { type: string; count: number }[];
  topPages: { url: string; count: number }[];
}

export function AnalyticsDashboard({ data }: { data: AnalyticsData }) {
  const maxEventCount = Math.max(...data.eventsByType.map((e) => e.count), 1);
  const maxPageCount = Math.max(...data.topPages.map((p) => p.count), 1);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Analytics</h1>
        <p className="text-slate-400 mt-1">Métricas de uso de los últimos 30 días</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-slate-800/60 bg-slate-900/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <BarChart3 className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{data.totalEvents.toLocaleString()}</p>
                <p className="text-xs text-slate-500">Eventos totales</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-slate-800/60 bg-slate-900/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-violet-500/10">
                <Eye className="h-5 w-5 text-violet-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{data.eventsByType.length}</p>
                <p className="text-xs text-slate-500">Tipos de evento</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-slate-800/60 bg-slate-900/50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <Globe className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{data.topPages.length}</p>
                <p className="text-xs text-slate-500">Páginas activas</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Events by Type */}
        <Card className="border-slate-800/60 bg-slate-900/50">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Monitor className="h-4 w-4" /> Eventos por Tipo
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.eventsByType.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-8">Sin datos de eventos</p>
            ) : (
              <div className="space-y-3">
                {data.eventsByType.map((event) => (
                  <div key={event.type} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300 font-mono">{event.type}</span>
                      <span className="text-slate-500">{event.count.toLocaleString()}</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-violet-500 rounded-full transition-all"
                        style={{ width: `${(event.count / maxEventCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Pages */}
        <Card className="border-slate-800/60 bg-slate-900/50">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Eye className="h-4 w-4" /> Páginas más Visitadas
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.topPages.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-8">Sin datos de páginas</p>
            ) : (
              <div className="space-y-3">
                {data.topPages.map((page) => (
                  <div key={page.url} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300 truncate max-w-[70%]">{page.url}</span>
                      <span className="text-slate-500">{page.count.toLocaleString()}</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 rounded-full transition-all"
                        style={{ width: `${(page.count / maxPageCount) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

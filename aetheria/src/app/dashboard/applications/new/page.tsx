"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ArrowLeft, Plus, Loader2 } from "lucide-react";
import Link from "next/link";

export default function NewApplicationPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    name: "",
    description: "",
    language: "",
    framework: "",
    repoUrl: "",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/applications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Error al crear la aplicación");
        return;
      }

      router.push(`/dashboard/applications/${data.id}`);
    } catch {
      setError("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Link
          href="/dashboard/applications"
          className="h-9 w-9 rounded-lg border border-border flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-surface transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Nueva Aplicación</h1>
          <p className="text-text-secondary text-sm mt-0.5">
            Registra una aplicación para analizar su seguridad
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Información de la Aplicación</CardTitle>
          <CardDescription>
            Proporciona los detalles básicos de la aplicación
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="name">Nombre *</Label>
              <Input
                id="name"
                placeholder="Mi Aplicación Web"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Descripción</Label>
              <textarea
                id="description"
                placeholder="Breve descripción de la aplicación..."
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={3}
                className="flex w-full rounded-lg border border-border bg-card px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-cyan-500/50 resize-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="language">Lenguaje</Label>
                <Input
                  id="language"
                  placeholder="TypeScript, Java, Python..."
                  value={form.language}
                  onChange={(e) => setForm({ ...form, language: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="framework">Framework</Label>
                <Input
                  id="framework"
                  placeholder="Next.js, Spring, Django..."
                  value={form.framework}
                  onChange={(e) => setForm({ ...form, framework: e.target.value })}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="repoUrl">URL del Repositorio</Label>
              <Input
                id="repoUrl"
                placeholder="https://github.com/org/repo"
                value={form.repoUrl}
                onChange={(e) => setForm({ ...form, repoUrl: e.target.value })}
              />
            </div>

            <div className="flex justify-end gap-3 pt-4">
              <Link href="/dashboard/applications">
                <Button variant="ghost" type="button">
                  Cancelar
                </Button>
              </Link>
              <Button variant="cyber" type="submit" disabled={loading}>
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Plus className="h-4 w-4 mr-2" />
                )}
                Crear Aplicación
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

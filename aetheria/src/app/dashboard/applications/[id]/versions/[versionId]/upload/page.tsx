"use client";

import { useState, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowLeft, Upload, Loader2, FileArchive, CheckCircle } from "lucide-react";

export default function UploadPage() {
  const params = useParams();
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<{
    fileSize: number;
    linesOfCode: number;
    fileCount: number;
  } | null>(null);
  const [error, setError] = useState("");

  const appId = params.id as string;
  const versionId = params.versionId as string;

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError("");
    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch(
        `/api/applications/${appId}/versions/${versionId}/upload`,
        { method: "POST", body: formData }
      );

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Error al subir archivo");
        return;
      }

      setResult(data);
    } catch {
      setError("Error de conexión");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-4">
        <Link href={`/dashboard/applications/${appId}`}>
          <Button variant="ghost" size="sm">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Subir Código Fuente</h1>
          <p className="text-text-secondary text-sm mt-1">
            Sube un archivo comprimido con el código fuente para análisis
          </p>
        </div>
      </div>

      {result ? (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="pt-6">
            <div className="text-center space-y-4">
              <CheckCircle className="h-12 w-12 text-emerald-400 mx-auto" />
              <h2 className="text-lg font-semibold text-text-primary">Archivo subido correctamente</h2>
              <div className="flex justify-center gap-6 text-sm text-text-primary">
                <span>{(result.fileSize / 1024 / 1024).toFixed(2)} MB</span>
                <span>{result.fileCount} archivos</span>
                <span>{result.linesOfCode.toLocaleString()} líneas</span>
              </div>
              <div className="flex gap-3 justify-center">
                <Button variant="cyber" onClick={() => router.push(`/dashboard/applications/${appId}`)}>
                  Volver a la Aplicación
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="text-base">Archivo de Código Fuente</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {error && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <div
              onClick={() => fileInputRef.current?.click()}
              className="flex flex-col items-center justify-center h-48 rounded-xl border-2 border-dashed border-border bg-surface cursor-pointer hover:border-cyan-500/40 hover:bg-cyan-500/5 transition-all"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip,.tar.gz,.tgz,.tar,.jar,.war,.7z,.rar"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              {file ? (
                <>
                  <FileArchive className="h-10 w-10 text-accent mb-3" />
                  <p className="text-sm font-medium text-text-primary">{file.name}</p>
                  <p className="text-xs text-text-muted mt-1">
                    {(file.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </>
              ) : (
                <>
                  <Upload className="h-10 w-10 text-text-muted mb-3" />
                  <p className="text-sm text-text-secondary">
                    Arrastra un archivo o haz clic para seleccionar
                  </p>
                  <p className="text-xs text-text-muted mt-1">Máximo 500MB</p>
                </>
              )}
            </div>

            {/* Supported formats */}
            <div className="rounded-lg border border-border bg-surface px-4 py-3">
              <p className="text-xs font-medium text-text-secondary mb-1.5">Formatos soportados:</p>
              <div className="flex flex-wrap gap-1.5">
                {[".zip", ".tar.gz", ".tgz", ".tar", ".jar", ".war", ".7z", ".rar"].map((fmt) => (
                  <span key={fmt} className="inline-flex items-center rounded-md bg-surface-hover px-2 py-0.5 text-[11px] font-mono text-accent/80 border border-border">
                    {fmt}
                  </span>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <Button
                variant="cyber"
                disabled={!file || uploading}
                onClick={handleUpload}
              >
                {uploading ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Upload className="h-4 w-4 mr-2" />
                )}
                Subir y Procesar
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

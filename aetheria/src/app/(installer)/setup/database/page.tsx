"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Database,
  Loader2,
  CheckCircle2,
  XCircle,
  ArrowRight,
  ArrowLeft,
  Link2,
  Settings2,
} from "lucide-react";
import { cn } from "@/lib/utils";

type DBProvider = "postgresql" | "sqlite" | "mysql";
type ProviderId = DBProvider | "mariadb" | "sqlserver" | "mongodb";

interface ProviderOption {
  value: ProviderId;
  /** Provider sent to the API — MariaDB speaks the MySQL protocol. */
  apiValue: DBProvider;
  label: string;
  description: string;
  defaultPort: string;
  disabled?: boolean;
}

const PROVIDERS: ProviderOption[] = [
  {
    value: "postgresql",
    apiValue: "postgresql",
    label: "PostgreSQL",
    description: "Recommended for production",
    defaultPort: "5432",
  },
  {
    value: "mysql",
    apiValue: "mysql",
    label: "MySQL",
    description: "Alternative production option",
    defaultPort: "3306",
  },
  {
    value: "mariadb",
    apiValue: "mysql",
    label: "MariaDB",
    description: "MySQL-compatible, fully supported",
    defaultPort: "3306",
  },
  {
    value: "sqlite",
    apiValue: "sqlite",
    label: "SQLite",
    description: "Not supported (text types) — use Docker Postgres for dev",
    defaultPort: "",
    disabled: true,
  },
  {
    value: "sqlserver",
    apiValue: "postgresql",
    label: "SQL Server",
    description: "Not supported yet (schema enums)",
    defaultPort: "1433",
    disabled: true,
  },
  {
    value: "mongodb",
    apiValue: "postgresql",
    label: "MongoDB",
    description: "Not supported (relational schema)",
    defaultPort: "27017",
    disabled: true,
  },
];

export default function DatabaseSetupPage() {
  const router = useRouter();

  const [provider, setProvider] = useState<ProviderId>("postgresql");

  /** Provider value sent to the setup API (MariaDB → mysql). */
  function apiProvider(): DBProvider {
    return provider === "mariadb" ? "mysql" : (provider as DBProvider);
  }

  /** URL scheme for the selected engine (MariaDB uses mysql://). */
  function urlScheme(): string {
    return provider === "mariadb" ? "mysql" : provider;
  }
  const [mode, setMode] = useState<"fields" | "url">("fields");

  // Field values
  const [host, setHost] = useState("localhost");
  const [port, setPort] = useState("5432");
  const [database, setDatabase] = useState("aetheria");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [connectionUrl, setConnectionUrl] = useState("");
  const [sqlitePath, setSqlitePath] = useState("./prisma/dev.db");

  // State
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    error?: string;
    latencyMs?: number;
  } | null>(null);
  const [initializing, setInitializing] = useState(false);
  const [initError, setInitError] = useState<string | null>(null);

  function handleProviderChange(newProvider: ProviderId) {
    const p = PROVIDERS.find((p) => p.value === newProvider);
    if (p?.disabled) return;
    setProvider(newProvider);
    setTestResult(null);
    setInitError(null);
    if (p?.defaultPort) setPort(p.defaultPort);
  }

  function buildUrl(): string {
    if (provider === "sqlite") {
      return sqlitePath.startsWith("file:")
        ? sqlitePath
        : `file:${sqlitePath}`;
    }

    if (mode === "url") {
      return connectionUrl;
    }

    const creds = user
      ? `${encodeURIComponent(user)}${password ? ":" + encodeURIComponent(password) : ""}@`
      : "";
    return `${urlScheme()}://${creds}${host}:${port}/${database}`;
  }

  async function handleTestConnection() {
    setTesting(true);
    setTestResult(null);

    try {
      const url = buildUrl();
      const res = await fetch("/api/setup/test-connection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: apiProvider(), connectionUrl: url }),
      });

      const data = await res.json();
      setTestResult(data);
    } catch {
      setTestResult({
        success: false,
        error: "Failed to reach the server. Is the application running?",
      });
    } finally {
      setTesting(false);
    }
  }

  async function handleInitialize() {
    setInitializing(true);
    setInitError(null);

    try {
      const url = buildUrl();
      const res = await fetch("/api/setup/initialize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: apiProvider(), connectionUrl: url }),
      });

      const data = await res.json();

      if (data.success) {
        router.push("/setup/admin");
      } else {
        setInitError(data.error || "Initialization failed");
      }
    } catch {
      setInitError("Failed to reach the server during initialization.");
    } finally {
      setInitializing(false);
    }
  }

  const connectionTested = testResult?.success === true;

  return (
    <div>
      <div className="text-center mb-6">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-cyan-500/10 border border-cyan-500/30 mb-3">
          <Database className="w-7 h-7 text-cyan-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-1">
          Database Configuration
        </h2>
        <p className="text-sm text-slate-400">
          Choose your database type and configure the connection
        </p>
      </div>

      {/* Provider selection */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        {PROVIDERS.map((p) => (
          <button
            key={p.value}
            type="button"
            onClick={() => handleProviderChange(p.value)}
            disabled={p.disabled}
            title={p.disabled ? p.description : undefined}
            className={cn(
              "p-4 rounded-lg border-2 transition-all text-center",
              p.disabled && "opacity-40 cursor-not-allowed",
              !p.disabled &&
                (provider === p.value
                  ? "border-cyan-500 bg-cyan-500/10"
                  : "border-slate-700/50 bg-slate-900/40 hover:border-slate-600")
            )}
          >
            <div
              className={cn(
                "text-sm font-bold mb-1",
                !p.disabled && provider === p.value ? "text-cyan-400" : "text-slate-300"
              )}
            >
              {p.label}
            </div>
            <div className="text-xs text-slate-500">{p.description}</div>
          </button>
        ))}
      </div>

      {/* SQLite config */}
      {provider === "sqlite" && (
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="sqlite-path">Database File Path</Label>
            <Input
              id="sqlite-path"
              value={sqlitePath}
              onChange={(e) => {
                setSqlitePath(e.target.value);
                setTestResult(null);
              }}
              placeholder="./prisma/dev.db"
            />
            <p className="text-xs text-slate-500">
              The database file will be created at this path if it doesn&apos;t
              exist.
            </p>
          </div>
        </div>
      )}

      {/* PostgreSQL / MySQL config */}
      {provider !== "sqlite" && (
        <div className="space-y-4">
          {/* Mode toggle */}
          <div className="flex gap-2 p-1 rounded-lg bg-slate-900/60 border border-slate-800">
            <button
              type="button"
              onClick={() => {
                setMode("fields");
                setTestResult(null);
              }}
              className={cn(
                "flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-md text-xs font-medium transition-all",
                mode === "fields"
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "text-slate-400 hover:text-slate-300"
              )}
            >
              <Settings2 className="w-4 h-4" />
              Individual Fields
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("url");
                setTestResult(null);
              }}
              className={cn(
                "flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-md text-xs font-medium transition-all",
                mode === "url"
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "text-slate-400 hover:text-slate-300"
              )}
            >
              <Link2 className="w-4 h-4" />
              Connection String
            </button>
          </div>

          {mode === "url" ? (
            <div className="space-y-2">
              <Label htmlFor="conn-url">Connection URL</Label>
              <Input
                id="conn-url"
                value={connectionUrl}
                onChange={(e) => {
                  setConnectionUrl(e.target.value);
                  setTestResult(null);
                }}
                placeholder={`${urlScheme()}://user:password@localhost:${port}/aetheria`}
              />
              <p className="text-xs text-slate-500">
                Full connection string including credentials
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2 col-span-2 sm:col-span-1">
                <Label htmlFor="host">Host</Label>
                <Input
                  id="host"
                  value={host}
                  onChange={(e) => {
                    setHost(e.target.value);
                    setTestResult(null);
                  }}
                  placeholder="localhost"
                />
              </div>
              <div className="space-y-2 col-span-2 sm:col-span-1">
                <Label htmlFor="port">Port</Label>
                <Input
                  id="port"
                  value={port}
                  onChange={(e) => {
                    setPort(e.target.value);
                    setTestResult(null);
                  }}
                  placeholder={PROVIDERS.find((p) => p.value === provider)?.defaultPort}
                />
              </div>
              <div className="space-y-2 col-span-2">
                <Label htmlFor="database">Database Name</Label>
                <Input
                  id="database"
                  value={database}
                  onChange={(e) => {
                    setDatabase(e.target.value);
                    setTestResult(null);
                  }}
                  placeholder="aetheria"
                />
              </div>
              <div className="space-y-2 col-span-2 sm:col-span-1">
                <Label htmlFor="user">Username</Label>
                <Input
                  id="user"
                  value={user}
                  onChange={(e) => {
                    setUser(e.target.value);
                    setTestResult(null);
                  }}
                  placeholder="postgres"
                />
              </div>
              <div className="space-y-2 col-span-2 sm:col-span-1">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setTestResult(null);
                  }}
                  placeholder="••••••••"
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Test result */}
      {testResult && (
        <div
          className={cn(
            "mt-4 p-3 rounded-lg border flex items-start gap-3",
            testResult.success
              ? "border-green-500/30 bg-green-500/10"
              : "border-red-500/30 bg-red-500/10"
          )}
        >
          {testResult.success ? (
            <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
          ) : (
            <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          )}
          <div className="text-sm">
            {testResult.success ? (
              <span className="text-green-400">
                Connection successful! Latency: {testResult.latencyMs}ms
              </span>
            ) : (
              <span className="text-red-400">{testResult.error}</span>
            )}
          </div>
        </div>
      )}

      {/* Init error */}
      {initError && (
        <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10">
          <p className="text-sm text-red-400">{initError}</p>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between mt-6">
        <Button
          variant="ghost"
          onClick={() => router.push("/setup")}
          disabled={testing || initializing}
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </Button>

        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={handleTestConnection}
            disabled={testing || initializing}
          >
            {testing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Testing...
              </>
            ) : (
              "Test Connection"
            )}
          </Button>

          <Button
            onClick={handleInitialize}
            disabled={!connectionTested || initializing}
          >
            {initializing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Initializing...
              </>
            ) : (
              <>
                Continue
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}

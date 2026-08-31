"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Cpu,
  Copy,
  Check,
  Terminal,
  Shield,
  Loader2,
  Key,
  Zap,
  FileCode,
  GitPullRequest,
  Search,
  BookOpen,
} from "lucide-react";
import { useLanguage } from "@/components/providers/language-provider";

export function McpIntegration() {
  const { t } = useLanguage();
  const [apiKeys, setApiKeys] = useState<{ id: string; name: string; keyPrefix: string }[]>([]);
  const [selectedKey, setSelectedKey] = useState("");
  const [activeIDE, setActiveIDE] = useState<"windsurf" | "cursor" | "claude" | "vscode">("windsurf");
  const [copied, setCopied] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchKeys = useCallback(async () => {
    const res = await fetch("/api/api-keys");
    if (res.ok) {
      const data = await res.json();
      const active = (data.keys || []).filter((k: { isActive: boolean }) => k.isActive);
      setApiKeys(active);
      if (active.length > 0) setSelectedKey(active[0].keyPrefix + "...");
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  function copyText(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  }

  function getConfig(ide: string) {
    const keyPlaceholder = selectedKey || "aeth_YOUR_API_KEY";

    if (ide === "windsurf") {
      return `{
  "mcpServers": {
    "aetheria-security": {
      "command": "npx",
      "args": ["-y", "@aetheria/mcp-server"],
      "env": {
        "EATHERIA_API_KEY": "${keyPlaceholder}",
        "EATHERIA_URL": "https://eatheria.com"
      }
    }
  }
}`;
    }

    if (ide === "cursor") {
      return `{
  "mcpServers": {
    "aetheria-security": {
      "command": "npx",
      "args": ["-y", "@aetheria/mcp-server"],
      "env": {
        "EATHERIA_API_KEY": "${keyPlaceholder}",
        "EATHERIA_URL": "https://eatheria.com"
      }
    }
  }
}`;
    }

    if (ide === "vscode") {
      return `{
  "github.copilot.chat.codeGeneration.instructions": [
    {
      "text": "Always scan code for security vulnerabilities using EATHERIA MCP"
    }
  ],
  "mcpServers": {
    "aetheria-security": {
      "command": "npx",
      "args": ["-y", "@aetheria/mcp-server"],
      "env": {
        "EATHERIA_API_KEY": "${keyPlaceholder}",
        "EATHERIA_URL": "https://eatheria.com"
      }
    }
  }
}`;
    }

    return `{
  "mcpServers": {
    "aetheria-security": {
      "command": "npx",
      "args": ["-y", "@aetheria/mcp-server"],
      "env": {
        "EATHERIA_API_KEY": "${keyPlaceholder}",
        "EATHERIA_URL": "https://eatheria.com"
      }
    }
  }
}`;
  }

  function getConfigPath(ide: string) {
    if (ide === "windsurf") return "~/.codeium/windsurf/mcp_config.json";
    if (ide === "cursor") return "~/.cursor/mcp.json";
    if (ide === "vscode") return "~/.vscode/mcp_settings.json (o settings.json)";
    return "claude_desktop_config.json";
  }

  const tools = [
    {
      name: "scan_code",
      icon: FileCode,
      description: t("dashboard.mcp.tool_scan_code_desc"),
      example: t("dashboard.mcp.tool_scan_code_example"),
      color: "cyan",
    },
    {
      name: "scan_file",
      icon: Search,
      description: t("dashboard.mcp.tool_scan_file_desc"),
      example: t("dashboard.mcp.tool_scan_file_example"),
      color: "violet",
    },
    {
      name: "create_fix_pr",
      icon: GitPullRequest,
      description: t("dashboard.mcp.tool_create_fix_pr_desc"),
      example: t("dashboard.mcp.tool_create_fix_pr_example"),
      color: "emerald",
    },
    {
      name: "trigger_repo_scan",
      icon: Zap,
      description: t("dashboard.mcp.tool_trigger_repo_scan_desc"),
      example: t("dashboard.mcp.tool_trigger_repo_scan_example"),
      color: "amber",
    },
    {
      name: "get_scan_status",
      icon: Terminal,
      description: t("dashboard.mcp.tool_get_scan_status_desc"),
      example: t("dashboard.mcp.tool_get_scan_status_example"),
      color: "blue",
    },
    {
      name: "explain_vulnerability",
      icon: BookOpen,
      description: t("dashboard.mcp.tool_explain_vulnerability_desc"),
      example: t("dashboard.mcp.tool_explain_vulnerability_example"),
      color: "rose",
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)]">MCP Server</h1>
        <p className="text-[var(--text-secondary)] mt-1">
          {t("dashboard.mcp.subtitle")}
        </p>
      </div>

      {/* How it works */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { step: "1", title: t("dashboard.mcp.step1Title"), desc: t("dashboard.mcp.step1Desc"), icon: Key },
          { step: "2", title: t("dashboard.mcp.step2Title"), desc: t("dashboard.mcp.step2Desc"), icon: Cpu },
          { step: "3", title: t("dashboard.mcp.step3Title"), desc: t("dashboard.mcp.step3Desc"), icon: Zap },
        ].map((s) => (
          <div
            key={s.step}
            className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-5 flex items-start gap-4"
          >
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center text-cyan-400 font-bold text-lg shrink-0">
              {s.step}
            </div>
            <div>
              <h3 className="text-sm font-semibold text-[var(--foreground)]">{s.title}</h3>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Config Generator */}
      <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-violet-500/20 to-purple-500/20 flex items-center justify-center">
            <Terminal className="h-5 w-5 text-violet-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-[var(--foreground)]">{t("dashboard.mcp.configTitle")}</h2>
            <p className="text-xs text-[var(--text-muted)]">
              {t("dashboard.mcp.configDesc")}
            </p>
          </div>
        </div>

        {/* API Key Selector */}
        {loading ? (
          <div className="flex items-center gap-2 mb-4 text-[var(--text-muted)] text-sm">
            <Loader2 className="h-4 w-4 animate-spin" /> {t("dashboard.mcp.loadingKeys")}
          </div>
        ) : apiKeys.length === 0 ? (
          <div className="mb-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-400">
            <strong>{t("dashboard.mcp.noKeysA")}</strong> {t("dashboard.mcp.noKeysB")}{" "}
            <a href="/dashboard/integrations/cicd" className="underline">
              CI/CD
            </a>{" "}
            {t("dashboard.mcp.noKeysC")}
          </div>
        ) : (
          <div className="mb-4 flex items-center gap-3">
            <label className="text-xs font-medium text-[var(--text-muted)]">API Key:</label>
            <select
              value={selectedKey}
              onChange={(e) => setSelectedKey(e.target.value)}
              className="h-8 rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 text-xs text-[var(--foreground)] focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
            >
              {apiKeys.map((k) => (
                <option key={k.id} value={k.keyPrefix + "..."}>
                  {k.name} ({k.keyPrefix}...)
                </option>
              ))}
            </select>
            <span className="text-[10px] text-[var(--text-muted)]">
              {t("dashboard.mcp.replaceKeyNote")}
            </span>
          </div>
        )}

        {/* IDE Tabs */}
        <div className="flex gap-1 rounded-lg bg-slate-800 p-1 mb-4">
          {(["windsurf", "cursor", "vscode", "claude"] as const).map((ide) => (
            <button
              key={ide}
              onClick={() => setActiveIDE(ide)}
              className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeIDE === ide
                  ? "bg-slate-700 text-white shadow-sm"
                  : "text-slate-300 hover:text-white hover:bg-slate-700/50"
              }`}
            >
              {ide === "windsurf" ? "Windsurf" : ide === "cursor" ? "Cursor" : ide === "vscode" ? "VSCode + Copilot" : "Claude Desktop"}
            </button>
          ))}
        </div>

        {/* Config path */}
        <div className="mb-2 flex items-center gap-2">
          <span className="text-xs text-[var(--text-muted)]">{t("dashboard.mcp.fileLabel")}</span>
          <code className="text-xs font-mono text-cyan-400">{getConfigPath(activeIDE)}</code>
        </div>

        {/* Config JSON */}
        <div className="relative">
          <pre className="rounded-lg bg-black/40 border border-[var(--border)] p-4 text-sm font-mono text-slate-300 overflow-x-auto">
            {getConfig(activeIDE)}
          </pre>
          <button
            onClick={() => copyText(getConfig(activeIDE), `config-${activeIDE}`)}
            className="absolute top-3 right-3 px-2.5 py-1.5 rounded-md bg-white/10 text-slate-400 hover:text-white hover:bg-white/20 transition-colors text-xs"
          >
            {copied === `config-${activeIDE}` ? (
              <Check className="h-3.5 w-3.5" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
          </button>
        </div>

        {/* Install note */}
        <div className="mt-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
          <p className="text-xs text-cyan-400">
            <strong>{t("dashboard.mcp.autoInstallA")}</strong> {t("dashboard.mcp.autoInstallB")}{" "}
            <code className="bg-black/30 px-1 rounded">npx -y @aetheria/mcp-server</code> {t("dashboard.mcp.autoInstallC")}
          </p>
        </div>
      </div>

      {/* Available Tools */}
      <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 flex items-center justify-center">
            <Zap className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-[var(--foreground)]">{t("dashboard.mcp.toolsTitle")}</h2>
            <p className="text-xs text-[var(--text-muted)]">
              {t("dashboard.mcp.toolsDesc")}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {tools.map((tool) => (
            <div
              key={tool.name}
              className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4 hover:border-[var(--border-hover)] transition-colors"
            >
              <div className="flex items-center gap-3 mb-2">
                <tool.icon className={`h-5 w-5 text-${tool.color}-400`} />
                <code className="text-sm font-mono font-semibold text-[var(--foreground)]">
                  {tool.name}
                </code>
              </div>
              <p className="text-xs text-[var(--text-muted)]">{tool.description}</p>
              <p className="text-[10px] text-[var(--text-muted)] mt-2 italic">
                {t("dashboard.mcp.examplePrefix")} {tool.example}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Licensing Notice */}
      <div className="rounded-lg border border-slate-500/20 bg-[var(--surface)] p-4 flex items-start gap-3">
        <Shield className="h-5 w-5 text-[var(--text-muted)] mt-0.5 shrink-0" />
        <div>
          <p className="text-sm text-[var(--foreground)] font-medium">{t("dashboard.mcp.licensingTitle")}</p>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            {t("dashboard.mcp.licensingBody")}
          </p>
        </div>
      </div>
    </div>
  );
}

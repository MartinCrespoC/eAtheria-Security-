"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Workflow,
  Key,
  Plus,
  Copy,
  Check,
  Trash2,
  Loader2,
  GitBranch,
  Shield,
  AlertCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useLanguage } from "@/components/providers/language-provider";

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  isActive: boolean;
  createdAt: string;
  createdBy?: { firstName: string; lastName: string; email: string };
}

export function CiCdIntegration() {
  const { t } = useLanguage();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyExpiry, setNewKeyExpiry] = useState("90");
  const [newKeyScopes, setNewKeyScopes] = useState(["analysis:create", "analysis:read"]);
  const [showCreate, setShowCreate] = useState(false);
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [activeTab, setActiveTab] = useState<"github" | "gitlab" | "generic">("github");

  const fetchKeys = useCallback(async () => {
    const res = await fetch("/api/api-keys");
    if (res.ok) {
      const data = await res.json();
      setKeys(data.keys || []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  function showMsg(type: "success" | "error", text: string) {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 5000);
  }

  async function createKey() {
    if (!newKeyName.trim()) return;
    setCreating(true);
    const res = await fetch("/api/api-keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: newKeyName,
        scopes: newKeyScopes,
        expiresInDays: newKeyExpiry === "never" ? null : parseInt(newKeyExpiry),
      }),
    });
    if (res.ok) {
      const data = await res.json();
      setRevealedKey(data.key);
      showMsg("success", t("dashboard.cicd.createdMsg"));
      await fetchKeys();
      setNewKeyName("");
    } else {
      const err = await res.json();
      showMsg("error", err.error || t("dashboard.cicd.createError"));
    }
    setCreating(false);
  }

  async function revokeKey(id: string) {
    if (!confirm(t("dashboard.cicd.revokeConfirm"))) return;
    const res = await fetch(`/api/api-keys/${id}`, { method: "DELETE" });
    if (res.ok) {
      showMsg("success", t("dashboard.cicd.revokedMsg"));
      await fetchKeys();
    } else {
      showMsg("error", t("dashboard.cicd.revokeError"));
    }
  }

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  }

  const githubYaml = `name: EATHERIA Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: EATHERIA Security Scan
        env:
          EATHERIA_API_KEY: \${{ secrets.EATHERIA_API_KEY }}
        run: |
          SCAN_RESULT=$(curl -sS -X POST https://eatheria.com/api/v1/scan \
            -H "Authorization: Bearer $EATHERIA_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
              \"repository\": \"$GITHUB_REPOSITORY\",
              \"branch\": \"$GITHUB_REF_NAME\",
              \"commit\": \"$GITHUB_SHA\",
              \"scanTypes\": [\"sast\", \"sca\"]
            }")
          echo "$SCAN_RESULT"`;

  const gitlabYaml = `aetheria-scan:
  stage: test
  image: node:20-alpine
  script:
    - |
      SCAN_RESULT=$(curl -s -X POST \\
        -H "Authorization: Bearer $EATHERIA_API_KEY" \\
        -H "Content-Type: application/json" \\
        -d '{
          "repository": "'$CI_PROJECT_PATH'",
          "branch": "'$CI_COMMIT_BRANCH'",
          "commit": "'$CI_COMMIT_SHA'",
          "scanTypes": ["sast", "sca"]
        }' \\
        https://eatheria.com/api/v1/scan)
      echo "$SCAN_RESULT"
  variables:
    EATHERIA_API_KEY: $EATHERIA_API_KEY`;

  const genericCurl = `# Trigger scan
curl -X POST https://eatheria.com/api/v1/scan \\
  -H "Authorization: Bearer aeth_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "repository": "owner/repo",
    "branch": "main",
    "commit": "abc1234",
    "scanTypes": ["sast", "sca"]
  }'

# Check status
curl https://eatheria.com/api/v1/scan/ANALYSIS_ID \\
  -H "Authorization: Bearer aeth_YOUR_API_KEY"`;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--foreground)]">CI/CD Integrations</h1>
        <p className="text-[var(--text-muted)] mt-1">
          {t("dashboard.cicd.subtitle")}
        </p>
      </div>

      {message && (
        <div className={`rounded-lg px-4 py-3 text-sm font-medium ${
          message.type === "success"
            ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
            : "bg-red-500/10 border border-red-500/30 text-red-400"
        }`}>
          {message.text}
        </div>
      )}

      {/* Revealed Key Banner */}
      {revealedKey && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-amber-400 mt-0.5 shrink-0" />
            <div className="flex-1">
              <h3 className="font-semibold text-amber-400">{t("dashboard.cicd.newKeyTitle")}</h3>
              <p className="text-sm text-amber-400/70 mt-1">
                {t("dashboard.cicd.newKeyWarning")}
              </p>
              <div className="mt-3 flex items-center gap-2">
                <code className="flex-1 bg-black/30 rounded-lg px-4 py-2.5 text-sm font-mono text-amber-300 select-all">
                  {revealedKey}
                </code>
                <button
                  onClick={() => copyToClipboard(revealedKey, "new-key")}
                  className="px-3 py-2.5 rounded-lg bg-amber-500/20 text-amber-400 hover:bg-amber-500/30 transition-colors"
                >
                  {copied === "new-key" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
              <button
                onClick={() => setRevealedKey(null)}
                className="mt-3 text-xs text-amber-500/60 hover:text-amber-400"
              >
                {t("dashboard.cicd.newKeyDismiss")}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* API Keys Section */}
      <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 flex items-center justify-center">
              <Key className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-[var(--foreground)]">API Keys</h2>
              <p className="text-xs text-[var(--text-muted)]">
                {t("dashboard.cicd.apiKeysDesc")}
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-sm font-medium"
          >
            <Plus className="h-4 w-4" />
            {t("dashboard.cicd.newApiKey")}
          </button>
        </div>

        {/* Create Form */}
        {showCreate && (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4 mb-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1.5 block">{t("dashboard.cicd.nameLabel")}</label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g. GitHub Actions, GitLab CI"
                  className="w-full h-9 rounded-lg border border-[var(--border)] bg-[var(--card)] px-3 text-sm text-[var(--foreground)] placeholder:text-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
                />
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1.5 block">{t("dashboard.cicd.expiryLabel")}</label>
                <select
                  value={newKeyExpiry}
                  onChange={(e) => setNewKeyExpiry(e.target.value)}
                  className="w-full h-9 rounded-lg border border-[var(--border)] bg-[var(--card)] px-3 text-sm text-[var(--foreground)] focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
                >
                  <option value="30">30 {t("dashboard.cicd.days")}</option>
                  <option value="90">90 {t("dashboard.cicd.days")}</option>
                  <option value="180">180 {t("dashboard.cicd.days")}</option>
                  <option value="365">1 {t("dashboard.cicd.year")}</option>
                  <option value="never">{t("dashboard.cicd.never")}</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-[var(--text-muted)] mb-1.5 block">Scopes</label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {["analysis:create", "analysis:read", "*"].map((scope) => (
                    <button
                      key={scope}
                      onClick={() =>
                        setNewKeyScopes((prev) =>
                          prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
                        )
                      }
                      className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-colors ${
                        newKeyScopes.includes(scope)
                          ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-400"
                          : "border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--foreground)]"
                      }`}
                    >
                      {scope}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 rounded-lg text-sm text-[var(--text-muted)] hover:text-[var(--foreground)] transition-colors"
              >
                {t("dashboard.cicd.cancel")}
              </button>
              <button
                onClick={createKey}
                disabled={creating || !newKeyName.trim()}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 text-white text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50"
              >
                {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Key className="h-4 w-4" />}
                {t("dashboard.cicd.createKey")}
              </button>
            </div>
          </div>
        )}

        {/* Keys List */}
        {loading ? (
          <div className="flex items-center justify-center h-24">
            <Loader2 className="h-6 w-6 animate-spin text-[var(--text-muted)]" />
          </div>
        ) : keys.length === 0 ? (
          <div className="text-center py-8 text-[var(--text-muted)]">
            <Key className="h-8 w-8 mx-auto mb-2 opacity-40" />
            <p className="text-sm">{t("dashboard.cicd.noKeys")}</p>
          </div>
        ) : (
          <div className="space-y-2">
            {keys.map((k) => (
              <div
                key={k.id}
                className={`flex items-center justify-between rounded-lg border p-3 transition-colors ${
                  k.isActive
                    ? "border-[var(--border)] bg-[var(--surface)]"
                    : "border-red-500/20 bg-red-500/5 opacity-60"
                }`}
              >
                <div className="flex items-center gap-3">
                  <Key className="h-4 w-4 text-[var(--text-muted)]" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-[var(--foreground)]">{k.name}</span>
                      <code className="text-[10px] font-mono text-[var(--text-muted)]">{k.keyPrefix}...</code>
                      <Badge variant={k.isActive ? "success" : "default"}>
                        {k.isActive ? t("dashboard.cicd.active") : t("dashboard.cicd.revoked")}
                      </Badge>
                    </div>
                    <div className="flex gap-4 mt-0.5 text-[10px] text-[var(--text-muted)]">
                      <span>Scopes: {k.scopes.join(", ")}</span>
                      {k.lastUsedAt && <span>{t("dashboard.cicd.lastUsed")}: {new Date(k.lastUsedAt).toLocaleDateString()}</span>}
                      {k.expiresAt && <span>{t("dashboard.cicd.expires")}: {new Date(k.expiresAt).toLocaleDateString()}</span>}
                      {k.createdBy && <span>{t("dashboard.cicd.by")}: {k.createdBy.firstName} {k.createdBy.lastName}</span>}
                    </div>
                  </div>
                </div>
                {k.isActive && (
                  <button
                    onClick={() => revokeKey(k.id)}
                    className="text-red-400/60 hover:text-red-400 transition-colors p-2"
                    title={t("dashboard.cicd.revoke")}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Setup Guide */}
      <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-violet-500/20 to-purple-500/20 flex items-center justify-center">
            <Workflow className="h-5 w-5 text-violet-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-[var(--foreground)]">{t("dashboard.cicd.pipelineTitle")}</h2>
            <p className="text-xs text-[var(--text-muted)]">
              {t("dashboard.cicd.pipelineDesc")}
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 rounded-lg bg-[var(--surface)] p-1 mb-4">
          {(["github", "gitlab", "generic"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "bg-[var(--card)] text-[var(--foreground)] shadow-sm"
                  : "text-[var(--text-muted)] hover:text-[var(--foreground)]"
              }`}
            >
              {tab === "github" && <GitBranch className="h-4 w-4" />}
              {tab === "gitlab" && <Shield className="h-4 w-4" />}
              {tab === "generic" && <Workflow className="h-4 w-4" />}
              {tab === "github" ? "GitHub Actions" : tab === "gitlab" ? "GitLab CI" : t("dashboard.cicd.tabGeneric")}
            </button>
          ))}
        </div>

        <div className="relative">
          <pre className="rounded-lg bg-black/40 border border-[var(--border)] p-4 text-sm font-mono text-slate-300 overflow-x-auto max-h-80">
            {activeTab === "github" ? githubYaml : activeTab === "gitlab" ? gitlabYaml : genericCurl}
          </pre>
          <button
            onClick={() => {
              const code = activeTab === "github" ? githubYaml : activeTab === "gitlab" ? gitlabYaml : genericCurl;
              copyToClipboard(code, `yaml-${activeTab}`);
            }}
            className="absolute top-3 right-3 px-2.5 py-1.5 rounded-md bg-white/10 text-slate-400 hover:text-white hover:bg-white/20 transition-colors text-xs"
          >
            {copied === `yaml-${activeTab}` ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        </div>

        {activeTab === "github" && (
          <div className="mt-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
            <p className="text-xs text-cyan-400">
              <strong>{t("dashboard.cicd.step1")}</strong> {t("dashboard.cicd.githubStep1")} <code>.github/workflows/eatheria.yml</code><br />
              <strong>{t("dashboard.cicd.step2")}</strong> {t("dashboard.cicd.githubStep2")} <code>EATHERIA_API_KEY</code><br />
              <strong>{t("dashboard.cicd.step3")}</strong> {t("dashboard.cicd.githubStep3")}
            </p>
          </div>
        )}

        {activeTab === "gitlab" && (
          <div className="mt-4 rounded-lg border border-violet-500/20 bg-violet-500/5 p-3">
            <p className="text-xs text-violet-400">
              <strong>{t("dashboard.cicd.step1")}</strong> {t("dashboard.cicd.gitlabStep1")} <code>.gitlab-ci.yml</code><br />
              <strong>{t("dashboard.cicd.step2")}</strong> {t("dashboard.cicd.gitlabStep2")} <code>EATHERIA_API_KEY</code> (masked)<br />
              <strong>{t("dashboard.cicd.step3")}</strong> {t("dashboard.cicd.gitlabStep3")}
            </p>
          </div>
        )}
      </div>

      {/* Licensing Notice */}
      <div className="rounded-lg border border-slate-500/20 bg-[var(--surface)] p-4 flex items-start gap-3">
        <Shield className="h-5 w-5 text-[var(--text-muted)] mt-0.5 shrink-0" />
        <div>
          <p className="text-sm text-[var(--foreground)] font-medium">{t("dashboard.cicd.licensingTitle")}</p>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            {t("dashboard.cicd.licensingBody")}
          </p>
        </div>
      </div>
    </div>
  );
}

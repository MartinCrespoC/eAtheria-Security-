<div align="center">

# 🛡️ AETHERIA Security Platform

**Open-source application security platform with AI-powered validation**
SAST · DAST · SCA · AI-assisted pentesting · All in a single instance

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma&logoColor=white)](https://www.prisma.io)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](aetheria/docker-compose.yml)
[![Security](https://img.shields.io/badge/OpenSSF-hardened-success)](.github/workflows/security-scan.yml)

</div>

---

## ⚡ Quick start (3 steps)

### Option A — Local

```bash
git clone https://github.com/MartinCrespoC/eAtheria-Security-.git && cd eAtheria-Security-/aetheria
./start.sh          # installs EVERYTHING and starts in production mode
```

### Option B — Docker (app + PostgreSQL + Redis)

```bash
git clone https://github.com/MartinCrespoC/eAtheria-Security-.git && cd eAtheria-Security-/aetheria
./start.sh docker
```

Open **http://localhost:3000** → the first-run wizard guides you through the rest (admin account + AI API key). **That's it.**

> `./start.sh` is bulletproof and idempotent: it checks Node 20+ (installs via nvm if missing), generates `.env` with random secrets, brings up PostgreSQL, applies the schema, seeds the rules catalog, builds and starts. Re-running it never breaks anything.

```bash
./start.sh dev      # development mode (hot reload)
./start.sh update   # git pull + reinstall + restart
```

---

## ✨ Features

| Module | Description |
|---|---|
| 🔬 **Multi-language SAST** | Custom taint-tracking engine (sources → sinks → sanitizers) with per-language rules |
| 🤖 **AI validation** | Findings are validated by AI to eliminate false positives before they're shown |
| 🕷️ **DAST** | Dynamic scanning of running applications |
| 📦 **SCA** | Dependency analysis and known-vulnerability detection (CVE) |
| 🐛 **BugHunter** | Curated real-world bug knowledge base (CWE → patterns → fixes) |
| 🎯 **Assisted pentesting** | AI-guided pentest flows with reproducible evidence |
| 📊 **OWASP benchmarks** | Measured against OWASP Benchmark / Juliet / WSTG with exportable reports |
| 🔌 **CI/CD** | Ready-to-use GitHub Action, GitLab CI and CLI for pipelines |
| 💬 **Notifications** | Telegram and WhatsApp (via Baileys — no browser needed) |
| 🔑 **MCP Server** | Exposes the engine as MCP tools for external agents |

## 🧠 Supported AI providers

Google Gemini · OpenAI · Anthropic · OpenRouter · DeepSeek · xAI · Mistral · Qwen · NVIDIA NIM · Perplexity · Azure OpenAI · Custom endpoint

**Models are discovered dynamically** from each provider's API — paste your API key, hit *Test connection* and the model list populates itself. Nothing hardcoded.

## 💻 Supported languages

**Dedicated taint rules:** JavaScript/TypeScript · Python · Java · PHP · C# · Ruby · Go · **ABAP/SAP**

**Generic coverage:** Kotlin · Swift · C · C++ · Rust · Scala · SQL · and more

## 📁 Uploads up to 1 GB

Upload complete projects as ZIP / 7z / RAR up to **1 GB**. Limit adjustable from Admin → Settings (`max_file_size_mb`).

---

## 🏗️ Stack

- **Framework:** Next.js 16 (App Router, Turbopack) + React 19 + TypeScript
- **Database:** PostgreSQL 16 + Prisma 6
- **Cache/queue:** Redis
- **Auth:** NextAuth (SRP, TOTP 2FA, scoped API keys)
- **UI:** Tailwind CSS 4 + custom components (dark/light, ES/EN i18n)

## 🔒 Project security

- No hardcoded secrets — everything via `.env` or environment variables
- Secrets scanning, rate limiting, CSP, audit logging, granularly-scoped API keys
- CI workflows with daily security scanning ([`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml))
- Dependabot enabled for npm and GitHub Actions
- Releases built and packaged by CI ([`release.yml`](.github/workflows/release.yml))

## 📖 Additional documentation

| Folder | Contents |
|---|---|
| [`cicd/`](aetheria/cicd) | CI/CD integration (pipeline examples) |
| [`github-action/`](aetheria/github-action) | Official GitHub Action |
| [`gitlab-ci/`](aetheria/gitlab-ci) | GitLab CI templates |
| [`mcp-server/`](aetheria/mcp-server) | Standalone MCP server |
| [`docker/`](aetheria/docker) | Container entrypoint and assets |

## 🤝 Contributing

Read **[CONTRIBUTING.md](CONTRIBUTING.md)** — PRs welcome.

## 📄 License

[MIT](LICENSE) © 2026 MartinCrespoC

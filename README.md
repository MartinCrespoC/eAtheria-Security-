<div align="center">

# 🛡️ AETHERIA Security Platform

**Plataforma open-source de seguridad de aplicaciones con validación por IA**
SAST · DAST · SCA · Pentesting asistido por IA · Todo en una sola instancia

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma&logoColor=white)](https://www.prisma.io)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Security](https://img.shields.io/badge/OpenSSF-hardened-success)](.github/workflows/security-scan.yml)

</div>

---

## ⚡ Inicio en 3 pasos

### Opción A — Local

```bash
git clone <repo-url> && cd aetheria
./start.sh          # instala TODO y arranca en producción
```

### Opción B — Docker (app + PostgreSQL + Redis)

```bash
git clone <repo-url> && cd aetheria
./start.sh docker
```

Abre **http://localhost:3000** → el wizard de primer arranque te guía (cuenta admin + API key de IA). **Eso es todo.**

> `./start.sh` es a prueba de errores e idempotente: verifica Node 20+ (instala vía nvm si falta), genera `.env` con secretos aleatorios, levanta PostgreSQL, aplica el schema, siembra el catálogo de reglas, compila y arranca. Re-ejecutarlo nunca rompe nada.

```bash
./start.sh dev      # modo desarrollo (hot reload)
./start.sh update   # git pull + reinstalar + reiniciar
```

---

## ✨ Características

| Módulo | Descripción |
|---|---|
| 🔬 **SAST multi-lenguaje** | Motor de taint-tracking propio (sources → sinks → sanitizers) con reglas por lenguaje |
| 🤖 **Validación por IA** | Los hallazgos se validan con IA para eliminar falsos positivos antes de mostrarse |
| 🕷️ **DAST** | Escaneo dinámico de aplicaciones en ejecución |
| 📦 **SCA** | Análisis de dependencias y vulnerabilidades conocidas (CVE) |
| 🐛 **BugHunter** | Base de conocimiento de bugs reales curada (CWE → patrones → fixes) |
| 🎯 **Pentesting asistido** | Flujos de pentest guiados por IA con evidencia reproducible |
| 📊 **Benchmarks OWASP** | Medición contra OWASP Benchmark / Juliet / WSTG con reportes exportables |
| 🔌 **CI/CD** | GitHub Action, GitLab CI y CLI listos para integrar en pipelines |
| 💬 **Notificaciones** | Telegram y WhatsApp (vía Baileys, sin browser) |
| 🔑 **MCP Server** | Expone el motor como herramientas MCP para agentes externos |

## 🧠 Proveedores de IA soportados

Google Gemini · OpenAI · Anthropic · OpenRouter · DeepSeek · xAI · Mistral · Qwen · NVIDIA NIM · Perplexity · Azure OpenAI · Endpoint custom

Los **modelos se descubren dinámicamente** desde la API de cada proveedor — pega tu API key, pulsa *Probar conexión* y la lista se puebla sola. Nada hardcodeado.

## 💻 Lenguajes soportados

**Reglas dedicadas de taint:** JavaScript/TypeScript · Python · Java · PHP · C# · Ruby · Go · **ABAP/SAP**

**Cobertura genérica:** Kotlin · Swift · C · C++ · Rust · Scala · SQL · y más

## 📁 Uploads hasta 1 GB

Sube proyectos completos en ZIP / 7z / RAR de hasta **1 GB**. Límite ajustable desde Admin → Configuración (`max_file_size_mb`).

---

## 🏗️ Stack

- **Framework:** Next.js 16 (App Router, Turbopack) + React 19 + TypeScript
- **DB:** PostgreSQL 16 + Prisma 6
- **Cache/queue:** Redis
- **Auth:** NextAuth (SRP-ready, 2FA TOTP, API keys con scopes)
- **UI:** Tailwind CSS 4 + componentes propios (dark/light, i18n ES/EN)

## 🔒 Seguridad del proyecto

- Sin secretos hardcodeados — todo vía `.env` o variables de entorno
- Secrets scan, rate limiting, CSP, audit logging, API keys con scopes granulares
- Workflows de CI con escaneo de seguridad diario ([`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml))
- Dependabot activado para npm y GitHub Actions
- Releases firmados y empaquetados por CI ([`release.yml`](.github/workflows/release.yml))

## 📖 Documentación adicional

| Carpeta | Contenido |
|---|---|
| [`cicd/`](aetheria/cicd) | Integración CI/CD (pipelines de ejemplo) |
| [`github-action/`](aetheria/github-action) | GitHub Action oficial |
| [`gitlab-ci/`](aetheria/gitlab-ci) | Templates para GitLab CI |
| [`mcp-server/`](aetheria/mcp-server) | Servidor MCP standalone |
| [`docker/`](aetheria/docker) | Entrypoint y assets de container |

## 🤝 Contribuir

Lee **[CONTRIBUTING.md](CONTRIBUTING.md)** — PRs bienvenidos.

## 📄 Licencia

[MIT](LICENSE) © 2026 MartinCrespoC

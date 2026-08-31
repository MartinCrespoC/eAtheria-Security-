# AETHERIA — CI/CD Integration Module

Todo lo necesario para integrar AETHERIA Security en tus pipelines:
escaneo automático, PR con fixes de IA, reporte PDF detallado y
servidor MCP remoto para agentes (Devin, Windsurf, Cursor, Claude).

```
cicd/
├── setup.sh                     # Instalación completa (plataforma + MCP + docker)
├── README.md                    # Esta guía (única fuente de verdad)
├── docker/
│   ├── Dockerfile.mcp           # Imagen del MCP server (modo remoto HTTP)
│   └── docker-compose.mcp.yml   # Stack MCP standalone
├── github -> ../github-action/  # GitHub Action (scan + fix-PR + PDF)
└── gitlab -> ../gitlab-ci/      # Template GitLab CI
```

---

## 1. Setup rápido

```bash
cd cicd
./setup.sh                                # instala todo (deps + build MCP + prisma)
./setup.sh --install-prereqs              # server de 0: instala Node 20 + Docker + git/zip (Debian/Ubuntu)
./setup.sh --install-prereqs --with-docker  # bootstrap completo desde cero
./setup.sh --with-docker                  # construye y levanta los contenedores
./setup.sh --help                         # opciones
```

Requisitos: Node.js ≥ 20, npm, y (opcional) Docker + Docker Compose —
`--install-prereqs` los instala por ti en Debian/Ubuntu (root o sudo).

### Server de 0 (ej. DigitalOcean droplet Ubuntu)

```bash
git clone <repo> && cd aetheria/cicd
./setup.sh --install-prereqs --with-docker
# → plataforma en :3000 con wizard de setup + MCP en :3100/mcp
```

La app en Docker es auto-contenida: levanta PostgreSQL + Redis, aplica
migraciones, siembra el catálogo y autogenera sus secretos; el wizard web
(al abrir el dominio) termina la configuración (admin, empresa, API key
de IA, WhatsApp opcional).

### Multi-dominio con Nginx Proxy Manager (nadro.dev + eatheria.com)

NPM soporta **N proxy hosts sobre el mismo puerto 80/443** — los dos
dominios conviven en la misma instancia sin conflicto:

1. **DNS**: crea registros `A` de `eatheria.com` (y `www.eatheria.com`) →
   IP del servidor (misma IP que nadro.dev).
2. **NPM Admin** (`:81`) → *Proxy Hosts → Add*:
   - Domain Names: `eatheria.com`, `www.eatheria.com`
   - Forward: `http` → `aetheria-app` → puerto `3000` (mismo contenedor
     que usa nadro.dev; ambos deben estar en la red docker `proxy`)
   - SSL: *Request a new certificate* (Let's Encrypt) + *Force SSL*.
3. **Dominio canónico**: la app usa NextAuth v4, donde `NEXTAUTH_URL` es
   un solo valor — los flujos de login/callback aterrizan siempre en ese
   dominio. Recomendado: en `.env` del server
   `NEXTAUTH_URL=https://eatheria.com` (rebuild) y en NPM convierte el
   host viejo en **Redirection Host** (301 → eatheria.com). Si prefieres
   mantener ambos vivos sin redirect, la app funciona en los dos, pero la
   autenticación siempre rebotará al canónico.

## 2. GitHub Actions (scan → comentario → PR de fixes → PDF)

Copia este workflow a tu repo como `.github/workflows/security.yml`:

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  aetheria-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write        # push de la rama de fixes
      pull-requests: write   # crear PR y comentar
    steps:
      - uses: actions/checkout@v4

      - name: AETHERIA Security Scan
        id: scan
        uses: MartinCrespoCalderon/eAtheria-Security/aetheria/github-action@main
        with:
          api-key: ${{ secrets.AETHERIA_API_KEY }}
          api-url: "https://aetheria.ikharoz.me"   # o tu self-host
          scan-types: "sast,sca"
          fail-on: "critical"
          comment-on-pr: "true"
          create-fix-pr: "true"   # abre PR con los fixes de IA
          pdf-report: "true"      # descarga reporte PDF detallado

      - name: Upload PDF report
        if: steps.scan.outputs.report-path != ''
        uses: actions/upload-artifact@v4
        with:
          name: aetheria-security-report
          path: ${{ steps.scan.outputs.report-path }}
          retention-days: 30
```

**Secret necesario**: `AETHERIA_API_KEY` (Dashboard → Settings → API Keys,
scope `analysis:create` + `analysis:read`).

**Outputs**: `scan-id`, `total-issues`, `critical-count`, `high-count`,
`status`, `report-path`, `fix-pr-url`.

Detalles completos en [`../github-action/README.md`](../github-action/README.md).

## 3. GitLab CI

Template listo en [`../gitlab-ci/aetheria-scan.yml`](../gitlab-ci/aetheria-scan.yml).
Añade las variables `AETHERIA_API_KEY` y `AETHERIA_API_URL` en
**Settings → CI/CD → Variables** (masked + protected).

## 4. API v1 (cualquier CI: Jenkins, Azure DevOps, scripts)

Todos los endpoints usan `Authorization: Bearer aeth_xxx`.

| Endpoint | Método | Uso |
|----------|--------|-----|
| `/api/v1/scan` | POST | Disparar escaneo (zipea el repo en base64 en `code`) |
| `/api/v1/scan/{id}` | GET | Estado + resultados (poll hasta `COMPLETED`) |
| `/api/v1/scan/{id}/report?format=pdf` | GET | **Reporte PDF detallado** (resumen, detalle por hallazgo, apéndice FP del AI triage) |
| `/api/v1/fix-pr` | POST | Genera `fixedCode` + diff por archivo vulnerable |

### Ejemplo mínimo (bash)

```bash
# 1. Escanear
SCAN_ID=$(curl -s -X POST "$AETHERIA_URL/api/v1/scan" \
  -H "Authorization: Bearer $AETHERIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"repository":"org/repo","branch":"main","scanTypes":["sast","sca"]}' | jq -r .id)

# 2. Esperar
until [ "$(curl -s "$AETHERIA_URL/api/v1/scan/$SCAN_ID" -H "Authorization: Bearer $AETHERIA_API_KEY" | jq -r .status)" = "COMPLETED" ]; do sleep 10; done

# 3. Descargar PDF
curl -s "$AETHERIA_URL/api/v1/scan/$SCAN_ID/report?format=pdf" \
  -H "Authorization: Bearer $AETHERIA_API_KEY" -o report.pdf
```

## 5. MCP server remoto (Devin, agentes cloud, CI bots)

El MCP habla **StreamableHTTP** para clientes que no pueden ejecutar un
proceso local. Cada request autentica con su propio Bearer (multi-tenant).

### Con Docker (recomendado)

```bash
cd cicd/docker
docker compose -f docker-compose.mcp.yml up -d --build
# → MCP en http://localhost:3100/mcp
```

### Sin Docker

```bash
cd mcp-server && npm ci && npm run build
MCP_TRANSPORT=http MCP_HTTP_PORT=3100 \
  AETHERIA_URL=https://aetheria.ikharoz.me \
  node dist/index.js
```

### Config del cliente (Devin / cualquier MCP remoto)

```json
{
  "mcpServers": {
    "aetheria-security": {
      "url": "https://tu-host:3100/mcp",
      "headers": { "Authorization": "Bearer aeth_tu_api_key" }
    }
  }
}
```

Clientes locales (Windsurf, Cursor, Claude Desktop) usan stdio — ver
[`../mcp-server/README.md`](../mcp-server/README.md).

### Herramientas MCP disponibles (14)

`scan_code` · `scan_file` · `trigger_repo_scan` (con `projectPath` y
`aiValidation`) · `get_scan_status` · `explain_vulnerability` ·
`create_fix_pr` · `triage_finding` · `compare_scans` · `get_threat_model` ·
`propose_hardening` · `generate_security_report` · `generate_writeup` ·
`audit_dependencies` · `analyze_security_headers`

## 6. Variables y parámetros

| Variable | Dónde | Descripción |
|----------|-------|-------------|
| `AETHERIA_API_KEY` | CI secret / MCP env | API key (`aeth_xxx`) |
| `AETHERIA_URL` | MCP env / action input `api-url` | URL de la plataforma |
| `MCP_TRANSPORT` | MCP env | `stdio` (default) · `http` · `all` |
| `MCP_HTTP_PORT` | MCP env | Puerto HTTP (default `3100`) |
| `aiValidation` | action/API/MCP | AI triage de hallazgos (default ON) |
| `fail-on` | GitHub Action | Gate de severidad: `critical`…`none` |

## 7. Flujo completo

```
push/PR ──► CI dispara scan (zip del repo) ──► plataforma:
              SAST/SCA determinista
              FP detector (patrones + gates ORM/JWT)
              AI triage (veredictos con evidencia citable)
            ◄── resultados + PDF
CI ──► comenta el PR · sube el PDF como artefacto
     ──► (opcional) /api/v1/fix-pr → rama aetheria/security-fixes-* → PR de fixes
     ──► gate: falla si ≥ fail-on
```

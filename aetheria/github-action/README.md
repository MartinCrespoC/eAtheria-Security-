# AETHERIA Security Scan — GitHub Action

Analiza tu código automáticamente en cada Pull Request con AETHERIA Security.

## Uso Rápido

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  aetheria-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: AETHERIA Security Scan
        uses: aetheria-security/scan-action@v1
        with:
          api-key: ${{ secrets.AETHERIA_API_KEY }}
          scan-types: "sast,sca"
          fail-on: "critical"
          comment-on-pr: "true"
```

## Inputs

| Input | Requerido | Default | Descripción |
|-------|-----------|---------|-------------|
| `api-key` | ✅ | — | Tu API key de AETHERIA (`aeth_xxx`) |
| `api-url` | ❌ | `https://app.aetheria.io` | URL de la API |
| `scan-types` | ❌ | `sast,sca` | Tipos de escaneo: `sast`, `sca`, `dast` |
| `fail-on` | ❌ | `critical` | Severidad mínima para fallar: `critical`, `high`, `medium`, `low`, `none` |
| `comment-on-pr` | ❌ | `true` | Comentar resultados en el PR |
| `create-fix-pr` | ❌ | `false` | Crear PR con fixes generados por IA |
| `pdf-report` | ❌ | `true` | Descargar reporte PDF detallado |

## Outputs

| Output | Descripción |
|--------|-------------|
| `scan-id` | ID del análisis en AETHERIA |
| `total-issues` | Total de vulnerabilidades encontradas |
| `critical-count` | Cantidad de vulnerabilidades críticas |
| `high-count` | Cantidad de vulnerabilidades altas |
| `status` | Estado del escaneo |
| `report-path` | Ruta del PDF descargado (`aetheria-security-report.pdf`) |
| `fix-pr-url` | URL del PR de fixes creado (si `create-fix-pr=true`) |

## Ejemplo completo: escaneo + PR de fixes + reporte PDF

```yaml
jobs:
  aetheria-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write       # para push de la rama de fixes
      pull-requests: write  # para crear el PR y comentar
    steps:
      - uses: actions/checkout@v4

      - name: AETHERIA Security Scan
        id: scan
        uses: aetheria-security/scan-action@v1
        with:
          api-key: ${{ secrets.AETHERIA_API_KEY }}
          scan-types: "sast,sca"
          fail-on: "critical"
          comment-on-pr: "true"
          create-fix-pr: "true"   # abre PR con los fixes de IA
          pdf-report: "true"      # descarga el PDF detallado

      - name: Upload PDF report
        if: steps.scan.outputs.report-path != ''
        uses: actions/upload-artifact@v4
        with:
          name: aetheria-security-report
          path: ${{ steps.scan.outputs.report-path }}
          retention-days: 30
```

El reporte PDF incluye: resumen por severidad, tabla de hallazgos, detalle
por vulnerabilidad (descripción + fix sugerido) y apéndice con los falsos
positivos descartados por el triage AI (con la razón citada).

## Obtener tu API Key

1. Inicia sesión en [AETHERIA](https://app.aetheria.io)
2. Ve a **Settings > API Keys**
3. Crea una nueva API key
4. Agrega la key como secret en tu repo: `Settings > Secrets > AETHERIA_API_KEY`

## Ejemplo: Bloquear PRs con vulnerabilidades altas

```yaml
- name: AETHERIA Scan
  id: scan
  uses: aetheria-security/scan-action@v1
  with:
    api-key: ${{ secrets.AETHERIA_API_KEY }}
    scan-types: "sast,sca"
    fail-on: "high"  # Falla si hay HIGH o CRITICAL
    comment-on-pr: "true"

- name: Check results
  if: always()
  run: |
    echo "Total issues: ${{ steps.scan.outputs.total-issues }}"
    echo "Critical: ${{ steps.scan.outputs.critical-count }}"
```

## Ejemplo: Escaneo completo con DAST

```yaml
- name: AETHERIA Full Scan
  uses: aetheria-security/scan-action@v1
  with:
    api-key: ${{ secrets.AETHERIA_API_KEY }}
    scan-types: "sast,sca,dast"
    fail-on: "medium"
```

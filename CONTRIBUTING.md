# Contribuir a AETHERIA

¡Gracias por tu interés en contribuir! Este documento explica cómo hacerlo de forma efectiva.

## Código de conducta

Sé respetuoso y constructivo. Este proyecto sigue el espíritu open-source: ayuda, comparte, no ataques.

## Cómo contribuir

### Reportar bugs

1. Busca primero en [Issues](../../issues) si ya existe.
2. Si no, abre uno nuevo incluyendo:
   - Pasos para reproducir
   - Comportamiento esperado vs. actual
   - Versión de Node/Docker, OS
   - Logs relevantes (`docker compose logs app` o salida de `start.sh`)

### Proponer features

Abre un issue con el tag `enhancement` describiendo el caso de uso antes de escribir código — así evitamos trabajo duplicado.

### Pull Requests

1. **Fork** y crea una rama descriptiva: `feat/mi-feature` o `fix/mi-bug`
2. **Setup local:**
   ```bash
   cd aetheria
   ./start.sh dev
   ```
3. **Reglas de código:**
   - TypeScript estricto — `npx tsc --noEmit` debe pasar sin errores
   - Sin secretos ni credenciales hardcodeadas (usa `.env`)
   - No agregues capas de compatibilidad hacia atrás: elimina paths obsoletos
   - Implementación más simple que cumpla el requisito completo
   - Validación server-side en toda entrada del usuario
4. **Tests:** si agregas funcionalidad, agrega tests (`npm test`)
5. **Commits:** mensajes claros en formato conventional commits:
   - `feat: ...` nueva funcionalidad
   - `fix: ...` corrección de bug
   - `docs: ...` solo documentación
   - `chore: ...` tooling/deps
6. Abre el PR contra `main` describiendo **qué** cambia y **por qué**

### Verificación antes del PR

```bash
cd aetheria
npx tsc --noEmit          # TypeScript limpio
npm run lint              # ESLint
npm test                  # Tests
```

## Seguridad

**No reportes vulnerabilidades de seguridad en issues públicos.** Contacta al mantenedor directamente. Ver `LICENSE` para alcance.

## Estructura del repo

```
aetheria/            # Aplicación principal (Next.js)
  src/               # Código fuente
  prisma/            # Schema + seeds
  scripts/           # Seeds y tooling
  docker/            # Entrypoint de container
  github-action/     # GitHub Action
  mcp-server/        # Servidor MCP
.github/workflows/   # CI (security scan, release)
```

## Licencia

Al contribuir aceptas que tu código se licencia bajo [MIT](LICENSE).

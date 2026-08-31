/**
 * EATHERIA Documentation System
 * Complete technical documentation for system administrators
 */

export interface DocumentationSection {
  id: string;
  title: string;
  icon: string;
  description: string;
  content: string;
  category: "architecture" | "usage" | "troubleshooting" | "api" | "security" | "deployment";
  tags: string[];
  lastUpdated: string;
}

export const DOCUMENTATION_SECTIONS: DocumentationSection[] = [
  {
    id: "getting-started",
    title: "Guía de Inicio - De 0 a 100",
    icon: "🚀",
    description: "Guía completa para usuarios sin experiencia en ciberseguridad",
    category: "usage",
    tags: ["inicio", "tutorial", "principiantes", "guía"],
    lastUpdated: "2026-06-06",
    content: `
# Guía de Inicio - De 0 a 100

## 👋 Bienvenido a EATHERIA

Esta guía está diseñada para usuarios **sin experiencia previa** en ciberseguridad. Te llevaremos paso a paso desde cero hasta que domines la plataforma.

---

## 📚 Conceptos Básicos (No necesitas ser experto)

### ¿Qué es EATHERIA?
EATHERIA es una plataforma que **analiza tu código automáticamente** para encontrar problemas de seguridad. Piensa en ello como un "corrector ortográfico" pero para seguridad en tu código.

### ¿Qué NO necesitas saber?
❌ No necesitas saber programación
❌ No necesitas saber de hacking
❌ No necesitas saber de servidores
❌ No necesitas configurar nada técnico

### ¿Qué SÍ hace EATHERIA por ti?
✅ Analiza tu código automáticamente
✅ Encuentra vulnerabilidades (problemas de seguridad)
✅ Te explica qué está mal en lenguaje simple
✅ Te dice cómo arreglarlo
✅ Usa Inteligencia Artificial para ayudarte

---

## 🎯 Paso 1: Primer Login (5 minutos)

### Acceder al Sistema
1. Abre tu navegador (Chrome, Firefox, Edge)
2. Ve a la URL que te dieron (ejemplo: \`https://aetheria.tuempresa.com\`)
3. Ingresa tu email y contraseña
4. Si es tu primera vez, te pedirá configurar **2FA** (autenticación de dos factores)

### ¿Qué es 2FA?
Es una capa extra de seguridad. Necesitarás:
- Tu contraseña (algo que sabes)
- Un código de tu teléfono (algo que tienes)

**Cómo configurarlo**:
1. Descarga Google Authenticator o Authy en tu teléfono
2. Escanea el código QR que aparece en pantalla
3. Ingresa el código de 6 dígitos que aparece en tu app
4. ¡Listo! Ya estás protegido

---

## 🏢 Paso 2: Entender tu Dashboard (10 minutos)

### Pantalla Principal
Cuando entres verás:

**📊 Dashboard**: Tu página de inicio
- Resumen de análisis recientes
- Gráficas de vulnerabilidades
- Estado de tus aplicaciones

**🎯 Aplicaciones**: Tus proyectos
- Aquí subes tu código
- Cada aplicación es un proyecto diferente

**🔍 Análisis**: Resultados de seguridad
- Vulnerabilidades encontradas
- Nivel de riesgo (Alto, Medio, Bajo)
- Cómo arreglar cada problema

**📚 Catálogo CWE**: Base de datos de vulnerabilidades
- Lista de todos los problemas conocidos
- No necesitas entenderlo todo, es referencia

---

## 📱 Paso 3: Crear tu Primera Aplicación (15 minutos)

### ¿Qué es una Aplicación?
Es simplemente un **proyecto** que quieres analizar. Puede ser:
- Una página web
- Una app móvil
- Un sistema interno
- Cualquier código que tengas

### Crear Aplicación - Paso a Paso

**1. Click en "Aplicaciones" en el menú**

**2. Click en "Nueva Aplicación"**

**3. Completa el formulario**:
\`\`\`
Nombre: Mi Primera App
Descripción: Página web de mi empresa
Tipo: WEB_APPLICATION
Lenguaje: JavaScript (o el que uses)
URL: https://miapp.com (opcional)
\`\`\`

**4. Click en "Crear"**

¡Listo! Ya tienes tu primera aplicación.

---

## 🔍 Paso 4: Tu Primer Análisis (20 minutos)

### Opción A: Análisis con IA (Recomendado)

**1. Entra a tu aplicación**
- Click en el nombre de tu app

**2. Click en "Nuevo Análisis con IA"**

**3. Selecciona qué analizar**:
- **SAST**: Analiza el código fuente
- **DAST**: Prueba la aplicación en vivo
- **Pentesting con IA**: Análisis completo automático

**4. Sube tu código** (si elegiste SAST):
- Arrastra tu carpeta de código
- O pega la URL de tu repositorio GitHub

**5. Click en "Iniciar Análisis"**

**6. Espera** (puede tomar 5-30 minutos):
- La IA está revisando tu código
- Puedes cerrar la ventana y volver después

### Opción B: Análisis Manual

Si prefieres no usar IA:
1. Click en "Nuevo Análisis Manual"
2. Sube tu código
3. Selecciona reglas de seguridad
4. Inicia análisis

---

## 📊 Paso 5: Entender los Resultados (30 minutos)

### Niveles de Riesgo

**🔴 CRÍTICO**: ¡Arreglar YA!
- Puede causar hackeo inmediato
- Ejemplo: Contraseñas en el código

**🟠 ALTO**: Arreglar esta semana
- Problema serio pero no inmediato
- Ejemplo: SQL Injection

**🟡 MEDIO**: Arreglar este mes
- Problema moderado
- Ejemplo: Falta de validación

**🟢 BAJO**: Arreglar cuando puedas
- Mejora recomendada
- Ejemplo: Falta de comentarios

**🔵 INFO**: Solo información
- No es un problema
- Ejemplo: Buenas prácticas

### Leer un Resultado

Cada vulnerabilidad muestra:

**1. Título**: Qué está mal
\`\`\`
CWE-79: Cross-Site Scripting (XSS)
\`\`\`

**2. Descripción Simple**:
\`\`\`
Tu aplicación permite que usuarios maliciosos
inyecten código JavaScript en tu página.
\`\`\`

**3. Dónde está el problema**:
\`\`\`
Archivo: login.js
Línea: 42
Código: document.innerHTML = userInput
\`\`\`

**4. Cómo arreglarlo**:
\`\`\`
Usa: textContent en lugar de innerHTML
O sanitiza el input con DOMPurify
\`\`\`

**5. Ejemplo de código correcto**:
\`\`\`javascript
// ❌ MAL
document.innerHTML = userInput;

// ✅ BIEN
document.textContent = userInput;
\`\`\`

---

## 🛠️ Paso 6: Arreglar Problemas (Variable)

### Proceso Recomendado

**1. Ordena por prioridad**:
- Primero CRÍTICO
- Luego ALTO
- Después MEDIO
- Al final BAJO

**2. Para cada problema**:
- Lee la descripción
- Ve el código afectado
- Copia el ejemplo de solución
- Aplícalo en tu código
- Prueba que funcione

**3. Vuelve a analizar**:
- Sube el código corregido
- Verifica que el problema desapareció

**4. Repite** hasta que no haya CRÍTICOS ni ALTOS

---

## 🤖 Paso 7: Usar la IA (Opcional pero Poderoso)

### ¿Qué puede hacer la IA?

**1. Explicarte en lenguaje simple**:
\`\`\`
Tú: "No entiendo qué es SQL Injection"
IA: "Es cuando un atacante puede modificar
     tus consultas a la base de datos..."
\`\`\`

**2. Generar código de solución**:
\`\`\`
Tú: "Cómo arreglo esta vulnerabilidad?"
IA: [Genera código específico para tu caso]
\`\`\`

**3. Analizar automáticamente**:
- La IA puede hacer pentesting completo
- Encuentra problemas que reglas normales no ven

### Cómo Usar la IA

**1. En cualquier vulnerabilidad**:
- Click en "Preguntar a la IA"
- Escribe tu pregunta en lenguaje normal
- La IA responde en español simple

**2. En Pentesting**:
- Click en "AI Pentesting"
- La IA hace todo el análisis
- Te da un reporte completo

---

## 📈 Paso 8: Monitorear tu Progreso (Continuo)

### Dashboard de Métricas

**Gráfica de Vulnerabilidades**:
- Ve cómo mejora tu seguridad con el tiempo
- Meta: Reducir CRÍTICOS y ALTOS a 0

**Análisis Recientes**:
- Historial de todos tus análisis
- Compara resultados

**Score de Seguridad**:
- Calificación de 0 a 100
- Meta: Llegar a 80+

### Reportes

**Generar Reporte**:
1. Click en "Reportes"
2. Selecciona período (última semana, mes, etc.)
3. Click en "Generar PDF"
4. Comparte con tu equipo

---

## 🎓 Glosario de Términos

### Términos que verás frecuentemente:

**CWE**: Common Weakness Enumeration
- Lista estándar de vulnerabilidades
- Ejemplo: CWE-79 = XSS

**CVE**: Common Vulnerabilities and Exposures
- Vulnerabilidades específicas conocidas
- Ejemplo: CVE-2024-1234

**SAST**: Static Application Security Testing
- Analiza el código sin ejecutarlo
- Busca problemas en el código fuente

**DAST**: Dynamic Application Security Testing
- Prueba la aplicación en ejecución
- Simula ataques reales

**Pentesting**: Penetration Testing
- Pruebas de hackeo ético
- Encuentra cómo un atacante entraría

**XSS**: Cross-Site Scripting
- Inyección de código JavaScript malicioso

**SQL Injection**: Inyección SQL
- Modificar consultas a la base de datos

**CSRF**: Cross-Site Request Forgery
- Hacer que usuarios hagan acciones sin querer

**False Positive**: Falso Positivo
- El sistema dice que hay un problema pero no lo hay
- EATHERIA filtra automáticamente muchos

---

## ❓ Preguntas Frecuentes

### "¿Necesito saber programar?"
No. Puedes usar EATHERIA solo para ver reportes. Si quieres arreglar problemas, necesitarás ayuda de un desarrollador.

### "¿Qué es MCP?"
Model Context Protocol. Es una forma de conectar herramientas. **No necesitas configurarlo**, ya está listo.

### "¿Qué es CI/CD?"
Continuous Integration/Continuous Deployment. Es automatización. **No es necesario para empezar**, es avanzado.

### "¿Cuánto cuesta analizar?"
Depende de tu plan. Ve a "Configuración → Plan" para ver tus límites.

### "¿Es seguro subir mi código?"
Sí. Todo está encriptado y solo tu empresa puede verlo. Tenemos certificaciones SOC 2 y GDPR.

### "¿Cada cuánto debo analizar?"
Recomendado:
- Antes de cada release: Siempre
- Código nuevo: Cada semana
- Código existente: Cada mes

### "¿Puedo automatizar los análisis?"
Sí, pero es avanzado. Contacta a soporte para ayuda con CI/CD.

---

## 🆘 Obtener Ayuda

### Dentro de la Plataforma
- **Icono de "?"**: Click en cualquier página para ayuda contextual
- **Documentación**: Menú → Documentación
- **Ejemplos**: Cada sección tiene ejemplos

### Soporte
- **Email**: support@aetheria.com
- **Chat**: Botón de chat en esquina inferior derecha
- **Teléfono**: +1-XXX-XXX-XXXX (horario de oficina)

### Recursos Externos
- **Videos tutoriales**: youtube.com/aetheria
- **Blog**: blog.aetheria.com
- **Comunidad**: community.aetheria.com

---

## ✅ Checklist de Éxito

Marca cuando completes cada paso:

- [ ] Login exitoso con 2FA configurado
- [ ] Dashboard explorado y entendido
- [ ] Primera aplicación creada
- [ ] Primer análisis completado
- [ ] Resultados revisados y entendidos
- [ ] Al menos 1 vulnerabilidad CRÍTICA arreglada
- [ ] Segundo análisis para verificar corrección
- [ ] Reporte generado y compartido
- [ ] IA probada al menos una vez
- [ ] Equipo capacitado en uso básico

---

## 🎯 Próximos Pasos

Una vez que domines lo básico:

**Nivel Intermedio**:
1. Configurar análisis automáticos
2. Integrar con GitHub/GitLab
3. Personalizar reglas de seguridad
4. Crear dashboards personalizados

**Nivel Avanzado**:
1. CI/CD integration
2. API usage
3. Custom scripts
4. Advanced AI prompts

**Recursos**:
- Ve a "Documentación → Guías Avanzadas"
- Contacta a tu Customer Success Manager

---

**🎉 ¡Felicidades! Ya sabes usar EATHERIA**

Recuerda: La seguridad es un proceso continuo, no un evento único. Analiza regularmente y mantén tu código seguro.

¿Preguntas? Usa el chat de soporte o el icono de ayuda (?) en cualquier página.
`,
  },
  {
    id: "architecture",
    title: "Arquitectura del Sistema",
    icon: "🏗️",
    description: "Arquitectura multi-tenant, domain separation y capas de seguridad",
    category: "architecture",
    tags: ["arquitectura", "multi-tenant", "seguridad", "database"],
    lastUpdated: "2026-06-06",
    content: `
# Arquitectura del Sistema EATHERIA

## Visión General

EATHERIA es una plataforma SaaS multi-tenant de análisis de seguridad con IA, construida con Next.js 15, Prisma ORM, y múltiples proveedores de IA.

## Arquitectura Multi-Tenant

### Domain Separation
- **Aislamiento completo de datos** por empresa (companyId)
- **Queries automáticos** con domain separation helper
- **Validación en cada request** para prevenir data leakage
- **Índices optimizados** para queries multi-tenant

### Capas de Seguridad

1. **Authentication Layer**
   - NextAuth.js con credenciales + 2FA
   - JWT tokens con refresh
   - Session management seguro
   - Rate limiting por usuario

2. **Authorization Layer**
   - Role-based access control (RBAC)
   - System Admin vs Company Admin
   - Permisos granulares por recurso
   - Impersonation con audit trail

3. **Data Layer**
   - Domain separation en Prisma
   - Row-level security
   - Encrypted sensitive data
   - Audit logging completo

## Stack Tecnológico

### Frontend
- **Next.js 15** (App Router)
- **React 18** con Server Components
- **TailwindCSS** para styling
- **Lucide Icons** para iconografía
- **Recharts** para visualizaciones

### Backend
- **Next.js API Routes**
- **Prisma ORM** con PostgreSQL
- **Zod** para validación
- **bcrypt** para passwords
- **JWT** para tokens

### IA & Análisis
- **Google Gemini** (Flash 2.0, Pro 1.5)
- **OpenAI GPT-4**
- **Anthropic Claude**
- **Custom analysis engine**
- **False positive detector**

### Database
- **PostgreSQL 14+**
- **Prisma migrations**
- **Índices optimizados**
- **Full-text search**

## Estructura de Directorios

\`\`\`
aetheria/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── (auth)/            # Auth pages
│   │   ├── (dashboard)/       # Dashboard pages
│   │   ├── admin/             # Admin pages
│   │   └── api/               # API routes
│   ├── components/            # React components
│   │   ├── ui/                # UI primitives
│   │   ├── admin/             # Admin components
│   │   └── dashboard/         # Dashboard components
│   ├── lib/                   # Core libraries
│   │   ├── ai/                # AI integrations
│   │   ├── analysis/          # Analysis engine
│   │   ├── security/          # Security utilities
│   │   ├── cwe/               # CWE database
│   │   └── false-positives/   # FP patterns
│   └── prisma/                # Database schema
├── scripts/                   # Utility scripts
└── tests/                     # E2E tests
\`\`\`

## Flujo de Datos

1. **Request** → Next.js API Route
2. **Auth** → Verificación de sesión
3. **Authorization** → Verificación de permisos
4. **Domain Separation** → Filtrado por companyId
5. **Business Logic** → Procesamiento
6. **Audit Log** → Registro de acción
7. **Response** → JSON al cliente

## Escalabilidad

- **Horizontal scaling** con load balancer
- **Database connection pooling**
- **Redis cache** para sessions
- **CDN** para assets estáticos
- **Background jobs** con queues
`,
  },
  {
    id: "company-management",
    title: "Gestión de Empresas",
    icon: "🏢",
    description: "Crear y administrar empresas (tenants) con aislamiento completo",
    category: "usage",
    tags: ["empresas", "multi-tenant", "administración"],
    lastUpdated: "2026-06-06",
    content: `
# Gestión de Empresas

## Crear Nueva Empresa

### Desde UI Admin
1. Navegar a **Admin → Companies**
2. Click en **"Nueva Empresa"**
3. Completar formulario:
   - Nombre de la empresa
   - Dominio (opcional)
   - Plan (Free, Pro, Enterprise)
   - Límites de usuarios
4. Click en **"Crear"**

### Desde API
\`\`\`typescript
POST /api/admin/companies
{
  "name": "Acme Corp",
  "domain": "acme.com",
  "plan": "ENTERPRISE",
  "maxUsers": 50
}
\`\`\`

## Configuración de Empresa

### AI Provider
Cada empresa puede tener su propio proveedor de IA:
- Gemini (Google)
- GPT-4 (OpenAI)
- Claude (Anthropic)

### Límites y Cuotas
- Usuarios máximos
- Aplicaciones máximas
- Análisis por mes
- Tokens de IA por mes

### Personalización
- Logo personalizado
- Colores de marca
- Dominio custom
- Email notifications

## Gestión de Usuarios

### Roles por Empresa
- **Company Admin**: Gestión completa de la empresa
- **User**: Acceso a aplicaciones y análisis
- **Viewer**: Solo lectura

### Invitar Usuarios
1. Admin → Users → Invite
2. Email del usuario
3. Seleccionar rol
4. Enviar invitación

## Domain Separation

### Garantías
✅ Los datos de una empresa **NUNCA** son visibles para otra
✅ Queries automáticos filtran por companyId
✅ Validación en cada request
✅ Audit logging de accesos

### Implementación
\`\`\`typescript
// Todas las queries incluyen companyId
const apps = await prisma.application.findMany({
  where: {
    companyId: session.user.companyId,
    // ... otros filtros
  }
});
\`\`\`

## Migración de Datos

### Export
\`\`\`bash
npm run export-company -- --id=<companyId>
\`\`\`

### Import
\`\`\`bash
npm run import-company -- --file=company-data.json
\`\`\`

## Eliminación de Empresa

⚠️ **ADVERTENCIA**: Esta acción es irreversible

1. Backup de datos
2. Notificar usuarios
3. Admin → Companies → Delete
4. Confirmar con password
5. Datos eliminados permanentemente
`,
  },
  {
    id: "ai-configuration",
    title: "Configuración de IA",
    icon: "🤖",
    description: "Configurar y gestionar proveedores de IA (Gemini, GPT-4, Claude)",
    category: "usage",
    tags: ["ia", "gemini", "gpt-4", "claude", "configuración"],
    lastUpdated: "2026-06-06",
    content: `
# Configuración de IA

## Proveedores Disponibles

### Google Gemini
- **Gemini 2.0 Flash**: Rápido, económico (análisis básicos)
- **Gemini 1.5 Pro**: Potente, contexto largo (análisis complejos)
- **Gemini 1.5 Flash**: Balance precio/rendimiento

### OpenAI
- **GPT-4 Turbo**: Máxima calidad
- **GPT-4**: Estable y confiable
- **GPT-3.5 Turbo**: Económico

### Anthropic
- **Claude 3 Opus**: Máxima capacidad
- **Claude 3 Sonnet**: Balance
- **Claude 3 Haiku**: Rápido

## Configuración por Empresa

### Asignar Provider
1. Admin → AI Providers
2. Seleccionar empresa
3. Elegir provider
4. Configurar API key
5. Guardar

### Variables de Entorno
\`\`\`bash
# Gemini
GOOGLE_GENERATIVE_AI_API_KEY=your_key_here

# OpenAI
OPENAI_API_KEY=your_key_here

# Anthropic
ANTHROPIC_API_KEY=your_key_here
\`\`\`

## Límites y Costos

### Gemini 2.0 Flash
- **Input**: $0.075 / 1M tokens
- **Output**: $0.30 / 1M tokens
- **Rate limit**: 2000 RPM

### GPT-4 Turbo
- **Input**: $10 / 1M tokens
- **Output**: $30 / 1M tokens
- **Rate limit**: 500 RPM

### Claude 3 Opus
- **Input**: $15 / 1M tokens
- **Output**: $75 / 1M tokens
- **Rate limit**: 1000 RPM

## Monitoreo de Uso

### Dashboard de Costos
- Tokens consumidos por mes
- Costo total por empresa
- Distribución por modelo
- Alertas de límites

### Optimización
1. Usar modelos apropiados por tarea
2. Cachear respuestas comunes
3. Limitar contexto a lo necesario
4. Batch requests cuando sea posible

## Fallback Strategy

Si un provider falla:
1. Retry con exponential backoff
2. Fallback a provider secundario
3. Queue para procesamiento posterior
4. Notificación a admins

## Mejores Prácticas

✅ **DO**:
- Rotar API keys regularmente
- Monitorear costos diariamente
- Configurar alertas de límites
- Usar modelos apropiados

❌ **DON'T**:
- Hardcodear API keys
- Usar siempre el modelo más caro
- Ignorar rate limits
- Enviar datos sensibles sin encriptar
`,
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting",
    icon: "🔧",
    description: "Solución de problemas comunes y debugging",
    category: "troubleshooting",
    tags: ["debugging", "errores", "problemas", "soluciones"],
    lastUpdated: "2026-06-06",
    content: `
# Troubleshooting

## Problemas Comunes

### 1. Error de Autenticación

**Síntoma**: "Invalid credentials" o "Session expired"

**Soluciones**:
\`\`\`bash
# Verificar variables de entorno
cat .env | grep NEXTAUTH

# Regenerar secret
openssl rand -base64 32

# Limpiar sessions
npm run prisma:studio
# Eliminar sessions expiradas
\`\`\`

### 2. Database Connection Timeout

**Síntoma**: "P2024: Timed out fetching a new connection"

**Soluciones**:
\`\`\`bash
# Verificar connection string
echo $DATABASE_URL

# Aumentar pool size
# En schema.prisma:
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
  pool_size = 20
}

# Reiniciar database
docker-compose restart postgres
\`\`\`

### 3. AI Provider Rate Limit

**Síntoma**: "429 Too Many Requests"

**Soluciones**:
- Implementar exponential backoff
- Usar queue system
- Distribuir requests en el tiempo
- Cambiar a plan superior

### 4. False Positives No Detectados

**Síntoma**: Patrones no se aplican en análisis

**Soluciones**:
\`\`\`typescript
// Verificar que el detector esté inicializado
import { falsePositiveDetector } from "@/lib/analysis/false-positive-detector";

await falsePositiveDetector.initialize();
const stats = falsePositiveDetector.getStats();
console.log(stats); // Verificar patrones cargados

// Reload patterns
await falsePositiveDetector.reload();
\`\`\`

### 5. CWE Sync Falla

**Síntoma**: "Failed to sync CWE data"

**Soluciones**:
\`\`\`bash
# Verificar conectividad
curl https://cwe.mitre.org/top25/

# Sync manual
npm run seed:cwe-2025
npm run seed:cwe-2024
npm run seed:cwe-2023

# Verificar datos
npm run prisma:studio
\`\`\`

## Logs y Debugging

### Habilitar Debug Mode
\`\`\`bash
# .env.local
DEBUG=true
LOG_LEVEL=debug
\`\`\`

### Ver Logs
\`\`\`bash
# Development
npm run dev

# Production
pm2 logs aetheria

# Database queries
DEBUG=prisma:query npm run dev
\`\`\`

### Audit Logs
\`\`\`sql
-- Ver últimas acciones
SELECT * FROM audit_logs
ORDER BY timestamp DESC
LIMIT 100;

-- Filtrar por usuario
SELECT * FROM audit_logs
WHERE user_id = 'user_id_here'
ORDER BY timestamp DESC;

-- Acciones críticas
SELECT * FROM audit_logs
WHERE severity IN ('HIGH', 'CRITICAL')
ORDER BY timestamp DESC;
\`\`\`

## Performance Issues

### Slow Queries
\`\`\`sql
-- Identificar queries lentas
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Crear índices
CREATE INDEX idx_apps_company ON applications(company_id);
CREATE INDEX idx_vulns_app ON vulnerabilities(application_id);
\`\`\`

### Memory Leaks
\`\`\`bash
# Monitorear memoria
node --inspect npm run dev

# Chrome DevTools → Memory profiler
# Buscar objetos que crecen indefinidamente
\`\`\`

## Backup y Recovery

### Backup Database
\`\`\`bash
# Backup completo
pg_dump -h localhost -U postgres aetheria > backup.sql

# Backup por empresa
pg_dump -h localhost -U postgres aetheria \
  --table=applications \
  --table=vulnerabilities \
  --where="company_id='company_id_here'" \
  > company_backup.sql
\`\`\`

### Restore
\`\`\`bash
# Restore completo
psql -h localhost -U postgres aetheria < backup.sql

# Restore selectivo
psql -h localhost -U postgres aetheria < company_backup.sql
\`\`\`

## Contacto de Soporte

Para problemas no resueltos:
- **Email**: support@aetheria.security
- **Slack**: #aetheria-support
- **GitHub Issues**: github.com/aetheria/issues
`,
  },
  {
    id: "api-reference",
    title: "API Reference",
    icon: "📡",
    description: "Documentación completa de endpoints y ejemplos de uso",
    category: "api",
    tags: ["api", "endpoints", "rest", "ejemplos"],
    lastUpdated: "2026-06-06",
    content: `
# API Reference

## Autenticación

Todos los endpoints requieren autenticación con JWT token.

### Obtener Token
\`\`\`bash
POST /api/auth/signin
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "password123"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { ... }
}
\`\`\`

### Usar Token
\`\`\`bash
Authorization: Bearer <token>
\`\`\`

## Companies API

### List Companies
\`\`\`bash
GET /api/admin/companies
Authorization: Bearer <token>

Response:
{
  "success": true,
  "companies": [
    {
      "id": "comp_123",
      "name": "Acme Corp",
      "plan": "ENTERPRISE",
      "userCount": 25,
      "createdAt": "2026-01-01T00:00:00Z"
    }
  ]
}
\`\`\`

### Create Company
\`\`\`bash
POST /api/admin/companies
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "New Company",
  "domain": "newco.com",
  "plan": "PRO",
  "maxUsers": 20
}

Response:
{
  "success": true,
  "company": { ... }
}
\`\`\`

### Update Company
\`\`\`bash
PATCH /api/admin/companies/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "plan": "ENTERPRISE",
  "maxUsers": 50
}
\`\`\`

### Delete Company
\`\`\`bash
DELETE /api/admin/companies/:id
Authorization: Bearer <token>
\`\`\`

## False Positives API

### List Patterns
\`\`\`bash
GET /api/admin/false-positives?language=javascript&isActive=true
Authorization: Bearer <token>

Response:
{
  "success": true,
  "patterns": [ ... ],
  "stats": {
    "total": 90,
    "active": 85,
    "byLanguage": {
      "javascript": 15,
      "python": 15,
      ...
    }
  }
}
\`\`\`

### Create Pattern
\`\`\`bash
POST /api/admin/false-positives
Authorization: Bearer <token>
Content-Type: application/json

{
  "language": "javascript",
  "pattern": "console\\\\.log\\\\(",
  "description": "Console logging",
  "reason": "Used for debugging",
  "context": "development",
  "cweIds": ["CWE-532"],
  "examples": ["console.log('debug')"]
}
\`\`\`

### Update Pattern
\`\`\`bash
PATCH /api/admin/false-positives/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "isActive": false
}
\`\`\`

### Delete Pattern
\`\`\`bash
DELETE /api/admin/false-positives/:id
Authorization: Bearer <token>
\`\`\`

## CWE Catalog API

### List CWEs
\`\`\`bash
GET /api/admin/cwe-catalog?year=2025
Authorization: Bearer <token>

Response:
{
  "success": true,
  "cwes": [
    {
      "id": "cwe_123",
      "cweId": "CWE-79",
      "name": "Cross-site Scripting",
      "year": 2025,
      "rank": 1,
      "kevCount": 7,
      "severity": "HIGH"
    }
  ]
}
\`\`\`

### Sync CWEs
\`\`\`bash
POST /api/admin/cwe-catalog/sync
Authorization: Bearer <token>
Content-Type: application/json

{
  "year": 2025
}

Response:
{
  "success": true,
  "synced": 25,
  "updated": 24,
  "created": 1
}
\`\`\`

## Analysis API

### Create Analysis
\`\`\`bash
POST /api/analysis
Authorization: Bearer <token>
Content-Type: application/json

{
  "applicationId": "app_123",
  "type": "FULL_SCAN",
  "options": {
    "includeFalsePositives": false,
    "aiProvider": "gemini"
  }
}

Response:
{
  "success": true,
  "analysisId": "analysis_456",
  "status": "PENDING"
}
\`\`\`

### Get Analysis Results
\`\`\`bash
GET /api/analysis/:id
Authorization: Bearer <token>

Response:
{
  "success": true,
  "analysis": {
    "id": "analysis_456",
    "status": "COMPLETED",
    "vulnerabilities": [ ... ],
    "falsePositivesFiltered": 12,
    "summary": { ... }
  }
}
\`\`\`

## Rate Limiting

- **Free**: 100 requests/hour
- **Pro**: 1000 requests/hour
- **Enterprise**: 10000 requests/hour

Headers:
\`\`\`
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
\`\`\`

## Error Codes

- **400**: Bad Request - Invalid input
- **401**: Unauthorized - Missing/invalid token
- **403**: Forbidden - Insufficient permissions
- **404**: Not Found - Resource doesn't exist
- **429**: Too Many Requests - Rate limit exceeded
- **500**: Internal Server Error - Server error
`,
  },
  {
    id: "security-best-practices",
    title: "Security Best Practices",
    icon: "🔐",
    description: "Configuración segura, compliance y mejores prácticas",
    category: "security",
    tags: ["seguridad", "compliance", "gdpr", "soc2", "mejores-prácticas"],
    lastUpdated: "2026-06-06",
    content: `
# Security Best Practices

## Configuración Segura

### Environment Variables
\`\`\`bash
# NUNCA commitear .env
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore

# Usar secrets management
# AWS Secrets Manager, HashiCorp Vault, etc.

# Rotar secrets regularmente
NEXTAUTH_SECRET=$(openssl rand -base64 32)
\`\`\`

### Database Security
\`\`\`sql
-- Usar SSL para conexiones
DATABASE_URL="postgresql://user:pass@host:5432/db?sslmode=require"

-- Crear usuario con permisos limitados
CREATE USER aetheria_app WITH PASSWORD 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aetheria_app;

-- Habilitar row-level security
ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
CREATE POLICY company_isolation ON applications
  USING (company_id = current_setting('app.company_id')::uuid);
\`\`\`

### API Keys
\`\`\`typescript
// Encriptar API keys en database
import { encrypt, decrypt } from '@/lib/crypto';

const encryptedKey = encrypt(apiKey);
await prisma.company.update({
  where: { id },
  data: { aiApiKey: encryptedKey }
});
\`\`\`

## Authentication & Authorization

### Password Policy
- Mínimo 12 caracteres
- Mayúsculas, minúsculas, números, símbolos
- No palabras comunes del diccionario
- Expiración cada 90 días
- No reutilizar últimas 5 passwords

### 2FA Obligatorio
\`\`\`typescript
// Forzar 2FA para admins
if (user.isSystemAdmin && !user.twoFactorEnabled) {
  return redirect('/setup-2fa');
}
\`\`\`

### Session Management
- Timeout: 30 minutos de inactividad
- Absolute timeout: 8 horas
- Logout en todos los dispositivos al cambiar password
- IP binding para sessions críticas

## Audit Logging

### Qué Loggear
✅ Logins exitosos y fallidos
✅ Cambios de permisos
✅ Creación/eliminación de recursos
✅ Acceso a datos sensibles
✅ Cambios de configuración
✅ Exportación de datos

### Formato de Logs
\`\`\`typescript
{
  timestamp: "2026-06-06T12:00:00Z",
  userId: "user_123",
  action: "DELETE",
  resourceType: "COMPANY",
  resourceId: "comp_456",
  ipAddress: "192.168.1.1",
  userAgent: "Mozilla/5.0...",
  severity: "HIGH",
  details: { ... }
}
\`\`\`

### Retención
- Logs de seguridad: 2 años
- Logs de acceso: 1 año
- Logs de debug: 30 días

## Data Protection

### Encryption at Rest
\`\`\`sql
-- PostgreSQL transparent encryption
ALTER DATABASE aetheria SET encryption = 'AES256';

-- Column-level encryption para datos sensibles
CREATE EXTENSION pgcrypto;
\`\`\`

### Encryption in Transit
\`\`\`nginx
# Nginx SSL config
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
\`\`\`

### Data Minimization
- Solo recolectar datos necesarios
- Anonimizar datos de analytics
- Eliminar datos al cerrar cuenta
- No almacenar datos de tarjetas (usar Stripe)

## Compliance

### GDPR
✅ Consentimiento explícito
✅ Right to access (export data)
✅ Right to erasure (delete account)
✅ Right to portability (JSON export)
✅ Data breach notification (72h)
✅ Privacy by design

### SOC 2
✅ Access controls
✅ Audit logging
✅ Encryption
✅ Incident response plan
✅ Vendor management
✅ Regular security assessments

### HIPAA (si aplica)
✅ BAA con clientes
✅ PHI encryption
✅ Access logs
✅ Breach notification
✅ Training anual

## Incident Response

### Plan de Respuesta
1. **Detección**: Monitoring y alertas
2. **Contención**: Aislar sistemas afectados
3. **Erradicación**: Eliminar amenaza
4. **Recuperación**: Restaurar servicios
5. **Lecciones**: Post-mortem y mejoras

### Contactos de Emergencia
- Security Team: security@aetheria.com
- On-call: +1-XXX-XXX-XXXX
- Legal: legal@aetheria.com

## Security Checklist

### Deployment
- [ ] SSL/TLS habilitado
- [ ] Secrets en vault (no .env)
- [ ] Database backups automáticos
- [ ] Monitoring y alertas configurados
- [ ] Rate limiting activo
- [ ] CORS configurado correctamente
- [ ] CSP headers configurados
- [ ] Dependency scanning (Snyk, Dependabot)

### Operación
- [ ] Revisar logs diariamente
- [ ] Actualizar dependencias semanalmente
- [ ] Rotar secrets mensualmente
- [ ] Security audit trimestral
- [ ] Penetration testing anual
- [ ] Disaster recovery drills semestrales

### Desarrollo
- [ ] Code review obligatorio
- [ ] SAST en CI/CD
- [ ] Dependency scanning
- [ ] Secret scanning
- [ ] No hardcodear credentials
- [ ] Input validation siempre
- [ ] Output encoding siempre
- [ ] Prepared statements para SQL
`,
  },
];

export function getDocumentationById(id: string): DocumentationSection | undefined {
  return DOCUMENTATION_SECTIONS.find((section) => section.id === id);
}

export function getDocumentationByCategory(
  category: DocumentationSection["category"]
): DocumentationSection[] {
  return DOCUMENTATION_SECTIONS.filter((section) => section.category === category);
}

export function searchDocumentation(query: string): DocumentationSection[] {
  const lowerQuery = query.toLowerCase();
  return DOCUMENTATION_SECTIONS.filter(
    (section) =>
      section.title.toLowerCase().includes(lowerQuery) ||
      section.description.toLowerCase().includes(lowerQuery) ||
      section.content.toLowerCase().includes(lowerQuery) ||
      section.tags.some((tag) => tag.toLowerCase().includes(lowerQuery))
  );
}

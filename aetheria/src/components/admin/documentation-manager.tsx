"use client";

import { useState } from "react";
import { Search, Book, ChevronRight, Sparkles, ExternalLink } from "lucide-react";

const DOCUMENTATION_CATALOG = {
  "getting-started": {
    title: "🚀 Primeros Pasos",
    sections: [
      {
        id: "installation",
        title: "Instalación y Configuración",
        content: `
# Instalación y Configuración

## 1. Requisitos Previos
- Node.js 18+
- PostgreSQL 14+
- API Key de Google AI (Gemini)

## 2. Instalación
\`\`\`bash
git clone https://github.com/MartinCrespoC/eAtheria-Security.git
cd eAtheria-Security/aetheria
npm install
\`\`\`

## 3. Configuración de Base de Datos
\`\`\`bash
npx prisma migrate dev
npx prisma db seed
\`\`\`

## 4. Variables de Entorno
Copia \`.env.example\` a \`.env\` y configura:
- DATABASE_URL
- NEXTAUTH_SECRET
- GOOGLE_API_KEY

## 5. Iniciar Servidor
\`\`\`bash
npm run dev
\`\`\`

Accede a http://localhost:3000
        `,
      },
      {
        id: "first-login",
        title: "Primer Login y Configuración Inicial",
        content: `
# Primer Login

## Usuario Administrador por Defecto
- Email: admin@aetheria.local
- Password: Admin123!

## Pasos Iniciales
1. **Cambiar contraseña**: Ve a Perfil → Cambiar Contraseña
2. **Configurar empresa**: Admin → Configuración de Empresa
3. **Configurar AI Provider**: Admin → Proveedores de IA
4. **Crear usuarios**: Admin → Usuarios
5. **Configurar licencia**: Admin → Licencias
        `,
      },
    ],
  },
  "ai-providers": {
    title: "🤖 Proveedores de IA",
    sections: [
      {
        id: "configure-provider",
        title: "Configurar Proveedor de IA",
        content: `
# Configurar Proveedor de IA

## Paso 1: Ir a Proveedores de IA
Navega a: **Admin → Proveedores de IA**

## Paso 2: Seleccionar Proveedor
Elige el proveedor que deseas configurar:
- **Google Gemini** (Recomendado)
- OpenAI GPT-4
- Anthropic Claude
- Y más...

## Paso 3: Configurar API Key
1. Click en **"Configurar"**
2. Pega tu API Key
3. Click en **"Guardar"**

## Paso 4: Activar Proveedor
1. Click en el toggle **"OFF"**
2. Cambiará a **"ON"**
3. ¡Listo! El proveedor está activo

## Paso 5: Asignar a Empresa
1. Ve a **Admin → Empresas**
2. Selecciona la empresa
3. En "Proveedor de IA", selecciona el proveedor
4. Guarda cambios

**Importante**: Cada empresa puede tener un proveedor diferente.
        `,
      },
      {
        id: "test-connection",
        title: "Probar Conexión",
        content: `
# Probar Conexión con IA

## Método 1: Desde Proveedores de IA
1. Ve a **Admin → Proveedores de IA**
2. Click en **"Test"** junto al proveedor
3. Verás un mensaje de éxito o error

## Método 2: Desde AI Pentesting
1. Ve a **AI Pentesting**
2. Pega código de prueba
3. Click en **"Analizar con IA"**
4. Si funciona, verás resultados

## Código de Prueba
\`\`\`javascript
// SQL Injection vulnerability
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
\`\`\`
        `,
      },
    ],
  },
  "ai-pentesting": {
    title: "🛡️ AI Pentesting",
    sections: [
      {
        id: "vulnerability-analysis",
        title: "Análisis de Vulnerabilidades",
        content: `
# Análisis de Vulnerabilidades con IA

## ¿Qué hace?
Analiza código fuente para detectar vulnerabilidades de seguridad usando IA.

## Cómo usar
1. Ve a **AI Pentesting**
2. Selecciona **"Análisis de Vulnerabilidades"**
3. Pega tu código en el editor
4. Selecciona profundidad:
   - **Quick**: Análisis rápido (< 30s)
   - **Standard**: Análisis estándar (< 2min)
   - **Deep**: Análisis profundo (< 5min)
   - **Exhaustive**: Análisis exhaustivo (< 15min)
5. Click **"Analizar con IA"**

## Resultados
Verás:
- **Vulnerabilidades encontradas** por severidad
- **Risk Score** (0-100)
- **Detalles** de cada vulnerabilidad
- **Fixes automáticos** generados por IA
- **Recomendaciones** estratégicas

## Ejemplo
\`\`\`javascript
// Código vulnerable
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});
\`\`\`

**Resultado**: Detectará SQL Injection (CWE-89, OWASP A03:2021)
        `,
      },
      {
        id: "exploit-generation",
        title: "Generación de Exploits",
        content: `
# Generación de Exploits (Educativo)

## ⚠️ IMPORTANTE
Solo para **testing autorizado** y **propósitos educativos**.

## Cómo usar
1. Ve a **AI Pentesting**
2. Selecciona **"Generador de Exploits"**
3. Describe la vulnerabilidad
4. Click **"Generar Exploit"**

## Resultado
Obtendrás:
- **Código del exploit** (Python, Bash, etc.)
- **Pasos de explotación** detallados
- **Resultado esperado**
- **Mitigaciones** para defenderse

## Uso Responsable
✅ Solo en sistemas propios
✅ Con autorización escrita
✅ Para mejorar seguridad
❌ Nunca en sistemas ajenos sin permiso
        `,
      },
      {
        id: "network-analysis",
        title: "Análisis de Red",
        content: `
# Análisis de Tráfico de Red

## ¿Qué hace?
Detecta anomalías y ataques en tráfico de red usando IA.

## Cómo usar
1. Captura tráfico de red (tcpdump, Wireshark)
2. Convierte a formato JSON
3. Ve a **AI Pentesting → Análisis de Red**
4. Sube el archivo JSON
5. Click **"Analizar"**

## Detecta
- Port scans
- DDoS attacks
- Brute force attempts
- Data exfiltration
- C2 communication
- Anomalías de tráfico

## Resultado
- **Amenazas detectadas** con severidad
- **Mapeo MITRE ATT&CK**
- **Reglas de firewall** generadas automáticamente
- **IPs sospechosas**
        `,
      },
      {
        id: "threat-intelligence",
        title: "Threat Intelligence",
        content: `
# Análisis de Threat Intelligence

## ¿Qué hace?
Analiza IOCs (Indicators of Compromise) con IA.

## Tipos de IOCs
- **IPs**: Direcciones IP sospechosas
- **Dominios**: Dominios maliciosos
- **Hashes**: Hashes de malware
- **URLs**: URLs maliciosas
- **CVEs**: Vulnerabilidades conocidas

## Cómo usar
1. Ve a **AI Pentesting → Threat Intelligence**
2. Ingresa tus IOCs
3. Click **"Analizar"**

## Resultado
- **Nivel de amenaza** por IOC
- **Threat actors** asociados
- **Campañas activas**
- **Reglas YARA** generadas
- **Recomendaciones** de acción
        `,
      },
    ],
  },
  "mcp-server": {
    title: "🌊 MCP Server",
    sections: [
      {
        id: "mcp-setup",
        title: "Configurar MCP Server",
        content: `
# Configurar MCP Server

## ¿Qué es MCP?
Model Context Protocol - Permite usar EATHERIA desde tu IDE.

## Instalación
\`\`\`bash
cd aetheria/mcp-server
npm install
npm run build
\`\`\`

## Configuración en Windsurf
Edita \`~/.codeium/windsurf/mcp_config.json\`:

\`\`\`json
{
  "mcpServers": {
    "aetheria-security": {
      "command": "node",
      "args": ["/ruta/absoluta/a/aetheria/mcp-server/dist/index.js"],
      "env": {
        "EATHERIA_API_KEY": "aeth_tu_api_key_aqui",
        "EATHERIA_URL": "https://aetheria.ikharoz.me"
      }
    }
  }
}
\`\`\`

## Uso
Reinicia Windsurf y pregunta:
- "Analiza este código para vulnerabilidades"
- "Escanea este archivo"
- "Genera un reporte de seguridad"

## 10 Herramientas Disponibles
1. scan_code
2. scan_file
3. trigger_repo_scan
4. get_scan_status
5. create_fix_pr
6. check_owasp_top10
7. analyze_security_headers
8. audit_dependencies
9. generate_security_report
10. explain_vulnerability
        `,
      },
    ],
  },
  "users-roles": {
    title: "👥 Usuarios y Roles",
    sections: [
      {
        id: "create-user",
        title: "Crear Usuario",
        content: `
# Crear Usuario

## Pasos
1. Ve a **Admin → Usuarios**
2. Click **"Nuevo Usuario"**
3. Completa el formulario:
   - Nombre
   - Email
   - Rol (Admin o Viewer)
   - Empresa
4. Click **"Crear"**

## Roles
- **System Admin**: Acceso total al sistema
- **Admin**: Gestión de su empresa
- **Viewer**: Solo lectura

## Primer Login
El usuario recibirá un email con instrucciones.
        `,
      },
    ],
  },
  "api-integration": {
    title: "🔌 Integración API",
    sections: [
      {
        id: "api-keys",
        title: "API Keys",
        content: `
# API Keys

## Crear API Key
1. Ve a **Dashboard → API Keys**
2. Click **"Nueva API Key"**
3. Asigna nombre y permisos
4. Copia la key (solo se muestra una vez)

## Usar API Key
\`\`\`bash
curl -X POST https://aetheria.ikharoz.me/api/ai/pentesting \\
  -H "Authorization: Bearer aeth_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "operation": "analyze-vulnerabilities",
    "code": "...",
    "analysisDepth": "deep"
  }'
\`\`\`

## Endpoints Disponibles
- POST /api/ai/pentesting
- POST /api/analysis/create
- GET /api/analysis/:id
        `,
      },
    ],
  },
  "troubleshooting": {
    title: "🔧 Solución de Problemas",
    sections: [
      {
        id: "common-errors",
        title: "Errores Comunes",
        content: `
# Errores Comunes

## "No active AI model found"
**Solución**:
1. Ve a Admin → Modelos de IA
2. Activa al menos un modelo
3. Configura el API key del provider

## "Rate limit exceeded"
**Solución**:
- Espera 1 minuto
- Reduce frecuencia de análisis
- Contacta admin para aumentar límites

## "Provider connection failed"
**Solución**:
1. Verifica API key
2. Click "Test" en el provider
3. Revisa logs del servidor

## Análisis muy lento
**Solución**:
- Usa analysisDepth: "quick"
- Divide archivos grandes
- Usa modelos más rápidos (Gemini Flash)
        `,
      },
    ],
  },
};

export function DocumentationManager() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedSection, setSelectedSection] = useState<string | null>(null);
  const [aiSearching, setAiSearching] = useState(false);
  const [aiResults, setAiResults] = useState<string | null>(null);

  const categories = Object.entries(DOCUMENTATION_CATALOG);

  const handleAISearch = async () => {
    if (!searchQuery.trim()) return;
    
    setAiSearching(true);
    setAiResults(null);

    try {
      // Buscar en toda la documentación
      const allContent = categories.flatMap(([catId, cat]) =>
        cat.sections.map(section => ({
          category: cat.title,
          section: section.title,
          content: section.content,
        }))
      );

      // Filtrar por relevancia
      const relevant = allContent.filter(item =>
        item.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.section.toLowerCase().includes(searchQuery.toLowerCase())
      );

      if (relevant.length > 0) {
        setAiResults(`Encontré ${relevant.length} resultado(s) relacionado(s) con "${searchQuery}":\n\n${
          relevant.map((r, i) => `${i + 1}. ${r.category} → ${r.section}`).join('\n')
        }`);
      } else {
        setAiResults(`No encontré resultados exactos para "${searchQuery}". Intenta con términos más generales como "configurar", "instalar", "API", etc.`);
      }
    } catch (error) {
      setAiResults("Error al buscar. Intenta de nuevo.");
    } finally {
      setAiSearching(false);
    }
  };

  const currentCategory = selectedCategory ? DOCUMENTATION_CATALOG[selectedCategory as keyof typeof DOCUMENTATION_CATALOG] : null;
  const currentSection = currentCategory && selectedSection
    ? currentCategory.sections.find(s => s.id === selectedSection)
    : null;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Sidebar - Catálogo */}
      <div className="lg:col-span-1 space-y-4">
        {/* Búsqueda IA */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            Búsqueda con IA
          </h3>
          <div className="space-y-2">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAISearch()}
              placeholder="¿Cómo configuro...?"
              className="w-full bg-slate-900 text-white px-3 py-2 rounded border border-slate-600 focus:border-cyan-400 focus:outline-none text-sm"
            />
            <button
              onClick={handleAISearch}
              disabled={aiSearching || !searchQuery.trim()}
              className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-600 text-white px-3 py-2 rounded text-sm font-medium flex items-center justify-center gap-2"
            >
              {aiSearching ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Buscando...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Buscar
                </>
              )}
            </button>
          </div>
          {aiResults && (
            <div className="mt-3 p-3 bg-slate-900 rounded text-sm text-slate-300 whitespace-pre-line">
              {aiResults}
            </div>
          )}
        </div>

        {/* Catálogo */}
        <div className="bg-slate-800 rounded-lg border border-slate-700 p-4">
          <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
            <Book className="w-5 h-5 text-cyan-400" />
            Catálogo
          </h3>
          <div className="space-y-1">
            {categories.map(([catId, cat]) => (
              <button
                key={catId}
                onClick={() => {
                  setSelectedCategory(catId);
                  setSelectedSection(null);
                }}
                className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                  selectedCategory === catId
                    ? "bg-cyan-500/20 text-cyan-400"
                    : "text-slate-300 hover:bg-slate-700"
                }`}
              >
                {cat.title}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="lg:col-span-3">
        {!selectedCategory ? (
          <div className="bg-slate-800 rounded-lg border border-slate-700 p-8 text-center">
            <Book className="w-16 h-16 text-slate-600 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">
              Bienvenido a la Documentación
            </h3>
            <p className="text-slate-400">
              Selecciona una categoría del catálogo o usa la búsqueda con IA
            </p>
          </div>
        ) : !selectedSection ? (
          <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
            <h2 className="text-2xl font-bold text-white mb-4">{currentCategory?.title}</h2>
            <div className="space-y-2">
              {currentCategory?.sections.map((section) => (
                <button
                  key={section.id}
                  onClick={() => setSelectedSection(section.id)}
                  className="w-full flex items-center justify-between p-4 bg-slate-900 hover:bg-slate-700 rounded-lg transition-colors text-left group"
                >
                  <span className="text-white font-medium">{section.title}</span>
                  <ChevronRight className="w-5 h-5 text-slate-400 group-hover:text-cyan-400" />
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="bg-slate-800 rounded-lg border border-slate-700 p-6">
            <button
              onClick={() => setSelectedSection(null)}
              className="text-cyan-400 hover:text-cyan-300 mb-4 flex items-center gap-2 text-sm"
            >
              ← Volver a {currentCategory?.title}
            </button>
            <div className="prose prose-invert prose-cyan max-w-none">
              <div
                className="text-slate-300"
                dangerouslySetInnerHTML={{
                  __html: currentSection?.content
                    .replace(/^# (.+)$/gm, '<h1 class="text-3xl font-bold text-white mb-4">$1</h1>')
                    .replace(/^## (.+)$/gm, '<h2 class="text-2xl font-bold text-white mt-6 mb-3">$1</h2>')
                    .replace(/^### (.+)$/gm, '<h3 class="text-xl font-semibold text-white mt-4 mb-2">$1</h3>')
                    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white">$1</strong>')
                    .replace(/```(\w+)?\n([\s\S]+?)```/g, '<pre class="bg-slate-900 p-4 rounded-lg overflow-x-auto my-4"><code class="text-cyan-400 text-sm">$2</code></pre>')
                    .replace(/`(.+?)`/g, '<code class="bg-slate-900 px-2 py-1 rounded text-cyan-400 text-sm">$1</code>')
                    .replace(/^- (.+)$/gm, '<li class="ml-4 mb-2">$1</li>')
                    .replace(/✅/g, '<span class="text-green-400">✅</span>')
                    .replace(/❌/g, '<span class="text-red-400">❌</span>')
                    .replace(/⚠️/g, '<span class="text-yellow-400">⚠️</span>')
                    || ''
                }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

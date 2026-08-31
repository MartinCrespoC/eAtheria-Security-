/**
 * Multi-language support system
 * Supports ES (Spanish) and EN (English)
 */

export type Language = "es" | "en";

export const translations = {
  es: {
    // Common
    common: {
      save: "Guardar",
      cancel: "Cancelar",
      delete: "Eliminar",
      edit: "Editar",
      create: "Crear",
      search: "Buscar",
      filter: "Filtrar",
      export: "Exportar",
      import: "Importar",
      loading: "Cargando...",
      error: "Error",
      success: "Éxito",
      warning: "Advertencia",
      info: "Información",
      yes: "Sí",
      no: "No",
      close: "Cerrar",
      back: "Volver",
      next: "Siguiente",
      previous: "Anterior",
      finish: "Finalizar",
    },
    // Navigation
    nav: {
      dashboard: "Dashboard",
      applications: "Aplicaciones",
      analysis: "Análisis",
      vulnerabilities: "Vulnerabilidades",
      github: "GitHub",
      settings: "Configuración",
      aiPentesting: "AI Pentesting",
      mcp: "MCP Server",
      admin: "Administración",
      users: "Usuarios",
      companies: "Empresas",
      licenses: "Licencias",
      aiProviders: "Proveedores de IA",
      aiModels: "Modelos de IA",
      documentation: "Documentación",
      cweCatalog: "Catálogo CWE",
      billing: "Facturación",
      profile: "Perfil",
      logout: "Cerrar Sesión",
    },
    // Help texts
    help: {
      dashboard: {
        title: "Dashboard Principal",
        short: "Vista general de tu seguridad",
        detailed: "El Dashboard muestra un resumen de todas las métricas de seguridad de tu empresa, incluyendo análisis recientes, vulnerabilidades encontradas, y tendencias de seguridad.",
      },
      aiPentesting: {
        title: "AI Pentesting",
        short: "Herramientas de pentesting con IA",
        detailed: "Utiliza inteligencia artificial avanzada para analizar código, generar exploits educativos, analizar tráfico de red y correlacionar amenazas. Incluye 8 herramientas profesionales.",
      },
      providers: {
        title: "Proveedores de IA",
        short: "Configura tus modelos de IA",
        detailed: "Gestiona los proveedores de IA disponibles (Gemini, GPT-4, Claude, etc.). Solo un provider puede estar activo a la vez. Cada empresa puede tener su propio provider asignado.",
      },
      companies: {
        title: "Gestión de Empresas",
        short: "Administra empresas del sistema",
        detailed: "Crea y gestiona empresas (tenants) con aislamiento completo de datos. Cada empresa tiene su propia configuración, usuarios, aplicaciones y datos. Domain separation garantizado.",
      },
      cweCatalog: {
        title: "Catálogo CWE",
        short: "Top 25 vulnerabilidades CWE por año",
        detailed: "Catálogo actualizable de las 25 vulnerabilidades más peligrosas según MITRE. Incluye datos de 2025, 2024, 2023 con ranking, KEV count y enlaces directos a la documentación oficial. Actualización manual desde MITRE.",
      },
      falsePositives: {
        title: "Falsos Positivos",
        short: "Patrones de falsos positivos por lenguaje",
        detailed: "Base de datos de patrones que no son vulnerabilidades reales. Incluye console.log, debugger, assertions, y otros patrones comunes de desarrollo. Se usa automáticamente en el análisis para reducir falsos positivos.",
      },
      documentation: {
        title: "Documentación del Sistema",
        short: "Guías completas para administradores",
        detailed: "Documentación técnica completa del sistema EATHERIA: arquitectura, guías de uso, troubleshooting, API reference, y mejores prácticas de seguridad. Solo accesible para System Admins.",
      },
      aiModels: {
        title: "Modelos de IA",
        short: "Gestiona modelos de IA disponibles",
        detailed: "Configura y gestiona los modelos de IA (Gemini, GPT-4, Claude, etc.). Cada modelo tiene costos, límites de tokens y capacidades específicas. Asigna modelos a diferentes tareas.",
      },
      security: {
        title: "Configuración de Seguridad",
        short: "Ajustes de seguridad del sistema",
        detailed: "Configura rate limiting, IPs bloqueadas, políticas de contraseñas, 2FA, sesiones, y otras configuraciones de seguridad. Incluye audit logging y alertas.",
      },
      analytics: {
        title: "Analytics y Métricas",
        short: "Estadísticas del sistema",
        detailed: "Visualiza métricas de uso, análisis realizados, vulnerabilidades encontradas, costos de IA, y tendencias. Exporta reportes y dashboards personalizados.",
      },
      tokens: {
        title: "API Tokens",
        short: "Gestiona tokens de API",
        detailed: "Crea y gestiona tokens de API para integraciones externas. Configura permisos, expiración, rate limits y revoca tokens comprometidos.",
      },
    },
  },
  en: {
    // Common
    common: {
      save: "Save",
      cancel: "Cancel",
      delete: "Delete",
      edit: "Edit",
      create: "Create",
      search: "Search",
      filter: "Filter",
      export: "Export",
      import: "Import",
      loading: "Loading...",
      error: "Error",
      success: "Success",
      warning: "Warning",
      info: "Information",
      yes: "Yes",
      no: "No",
      close: "Close",
      back: "Back",
      next: "Next",
      previous: "Previous",
      finish: "Finish",
    },
    // Navigation
    nav: {
      dashboard: "Dashboard",
      applications: "Applications",
      analysis: "Analysis",
      vulnerabilities: "Vulnerabilities",
      github: "GitHub",
      settings: "Settings",
      aiPentesting: "AI Pentesting",
      mcp: "MCP Server",
      admin: "Administration",
      users: "Users",
      companies: "Companies",
      licenses: "Licenses",
      aiProviders: "AI Providers",
      aiModels: "AI Models",
      documentation: "Documentation",
      cweCatalog: "CWE Catalog",
      billing: "Billing",
      profile: "Profile",
      logout: "Logout",
    },
    // Help texts
    help: {
      dashboard: {
        title: "Main Dashboard",
        short: "Overview of your security",
        detailed: "The Dashboard shows a summary of all your company's security metrics, including recent analyses, found vulnerabilities, and security trends.",
      },
      aiPentesting: {
        title: "AI Pentesting",
        short: "AI-powered pentesting tools",
        detailed: "Use advanced artificial intelligence to analyze code, generate educational exploits, analyze network traffic, and correlate threats. Includes 8 professional tools.",
      },
      providers: {
        title: "AI Providers",
        short: "Configure your AI models",
        detailed: "Manage available AI providers (Gemini, GPT-4, Claude, etc.). Only one provider can be active at a time. Each company can have its own assigned provider.",
      },
      companies: {
        title: "Company Management",
        short: "Manage system companies",
        detailed: "Create and manage companies (tenants) with complete data isolation. Each company has its own configuration, users, applications, and data. Domain separation guaranteed.",
      },
      cweCatalog: {
        title: "CWE Catalog",
        short: "Top 25 CWE vulnerabilities per year",
        detailed: "Updateable catalog of the 25 most dangerous vulnerabilities according to MITRE. Includes data from 2025, 2024, 2023 with ranking, KEV count, and direct links to official documentation. Manual update from MITRE.",
      },
      falsePositives: {
        title: "False Positives",
        short: "False positive patterns by language",
        detailed: "Database of patterns that are not real vulnerabilities. Includes console.log, debugger, assertions, and other common development patterns. Used automatically in analysis to reduce false positives.",
      },
      documentation: {
        title: "System Documentation",
        short: "Complete guides for administrators",
        detailed: "Complete technical documentation of the EATHERIA system: architecture, usage guides, troubleshooting, API reference, and security best practices. Only accessible to System Admins.",
      },
      aiModels: {
        title: "AI Models",
        short: "Manage available AI models",
        detailed: "Configure and manage AI models (Gemini, GPT-4, Claude, etc.). Each model has specific costs, token limits, and capabilities. Assign models to different tasks.",
      },
      security: {
        title: "Security Configuration",
        short: "System security settings",
        detailed: "Configure rate limiting, blocked IPs, password policies, 2FA, sessions, and other security settings. Includes audit logging and alerts.",
      },
      analytics: {
        title: "Analytics and Metrics",
        short: "System statistics",
        detailed: "View usage metrics, analyses performed, vulnerabilities found, AI costs, and trends. Export reports and custom dashboards.",
      },
      tokens: {
        title: "API Tokens",
        short: "Manage API tokens",
        detailed: "Create and manage API tokens for external integrations. Configure permissions, expiration, rate limits, and revoke compromised tokens.",
      },
    },
  },
};

export function t(lang: Language, key: string): string {
  const keys = key.split(".");
  let value: any = translations[lang];

  for (const k of keys) {
    value = value?.[k];
    if (value === undefined) {
      console.warn(`Translation missing: ${lang}.${key}`);
      return key;
    }
  }

  return typeof value === "string" ? value : key;
}

export function getHelpText(lang: Language, section: string) {
  const help = translations[lang].help[section as keyof typeof translations.es.help];
  return help || {
    title: section,
    short: "Help not available",
    detailed: "Help text not configured for this section.",
  };
}

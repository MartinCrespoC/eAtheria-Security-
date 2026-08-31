/**
 * Scan Progress — In-memory event store + pub/sub for real-time scan tracking.
 * Emits granular progress events that auditors and users can follow step-by-step.
 * No AI model/provider details are exposed — only general methodology info.
 */

export interface ScanLogEntry {
  timestamp: number;
  level: "info" | "success" | "warning" | "error" | "debug";
  message: string;
  details?: string;
}

export interface ScanStep {
  id: string;
  label: string;
  description: string;
  status: "pending" | "running" | "completed" | "skipped" | "error";
  progress: number; // 0-100
  startedAt?: number;
  completedAt?: number;
  metadata?: Record<string, string | number>;
}

export interface ScanProgressState {
  analysisId: string;
  status: "queued" | "running" | "completed" | "failed";
  overallProgress: number; // 0-100
  currentPhase: string;
  scanLevel: string;
  scanTypes: string[];
  steps: ScanStep[];
  logs: ScanLogEntry[];
  stats: {
    filesDiscovered: number;
    filesAnalyzed: number;
    languagesDetected: string[];
    dependenciesFound: number;
    vulnerabilitiesFound: number;
    falsePositivesDetected: number;
    linesOfCode: number;
  };
  startedAt: number;
  completedAt?: number;
  error?: string;
}

type Listener = (state: ScanProgressState) => void;

class ScanProgressStore {
  private states = new Map<string, ScanProgressState>();
  private listeners = new Map<string, Set<Listener>>();
  private readonly MAX_LOGS = 500;

  getState(analysisId: string): ScanProgressState | undefined {
    return this.states.get(analysisId);
  }

  init(analysisId: string, scanTypes: string[], scanLevel: string): ScanProgressState {
    const state: ScanProgressState = {
      analysisId,
      status: "queued",
      overallProgress: 0,
      currentPhase: "Inicializando",
      scanLevel,
      scanTypes,
      steps: this.buildSteps(scanTypes),
      logs: [],
      stats: {
        filesDiscovered: 0,
        filesAnalyzed: 0,
        languagesDetected: [],
        dependenciesFound: 0,
        vulnerabilitiesFound: 0,
        falsePositivesDetected: 0,
        linesOfCode: 0,
      },
      startedAt: Date.now(),
    };
    this.states.set(analysisId, state);
    return state;
  }

  private buildSteps(scanTypes: string[]): ScanStep[] {
    const steps: ScanStep[] = [
      {
        id: "discovery",
        label: "Descubrimiento de archivos",
        description: "Identificando archivos fuente, dependencias y estructura del proyecto",
        status: "pending",
        progress: 0,
      },
    ];

    if (scanTypes.includes("SAST")) {
      steps.push({
        id: "sast",
        label: "Análisis estático (SAST)",
        description: "Escaneo de patrones de vulnerabilidad en código fuente",
        status: "pending",
        progress: 0,
      });
    }

    if (scanTypes.includes("SCA")) {
      steps.push({
        id: "sca",
        label: "Análisis de dependencias (SCA)",
        description: "Verificación de vulnerabilidades conocidas en librerías (CVE/OSV)",
        status: "pending",
        progress: 0,
      });
      steps.push({
        id: "sbom",
        label: "Generación de SBOM",
        description: "Inventario de componentes de software (CycloneDX)",
        status: "pending",
        progress: 0,
      });
    }

    if (scanTypes.includes("DAST")) {
      steps.push({
        id: "dast",
        label: "Análisis dinámico (DAST)",
        description: "Pruebas de seguridad en tiempo de ejecución",
        status: "pending",
        progress: 0,
      });
    }

    steps.push({
      id: "fp-detection",
      label: "Detección de falsos positivos",
      description: "Validación cruzada con base de conocimiento de patrones seguros",
      status: "pending",
      progress: 0,
    });

    steps.push({
      id: "report",
      label: "Generación de reporte",
      description: "Consolidación de resultados y métricas de seguridad",
      status: "pending",
      progress: 0,
    });

    return steps;
  }

  update(analysisId: string, updater: (state: ScanProgressState) => void) {
    const state = this.states.get(analysisId);
    if (!state) return;
    updater(state);
    this.recalculateProgress(state);
    this.notify(analysisId, state);
  }

  log(analysisId: string, level: ScanLogEntry["level"], message: string, details?: string) {
    const state = this.states.get(analysisId);
    if (!state) return;
    state.logs.push({ timestamp: Date.now(), level, message, details });
    if (state.logs.length > this.MAX_LOGS) {
      state.logs = state.logs.slice(-this.MAX_LOGS);
    }
    this.notify(analysisId, state);
  }

  updateStep(analysisId: string, stepId: string, updates: Partial<ScanStep>) {
    const state = this.states.get(analysisId);
    if (!state) return;
    const step = state.steps.find((s) => s.id === stepId);
    if (!step) return;
    Object.assign(step, updates);
    if (updates.status === "running" && !step.startedAt) step.startedAt = Date.now();
    if (updates.status === "completed" || updates.status === "skipped") step.completedAt = Date.now();
    this.recalculateProgress(state);
    this.notify(analysisId, state);
  }

  complete(analysisId: string) {
    const state = this.states.get(analysisId);
    if (!state) return;
    state.status = "completed";
    state.overallProgress = 100;
    state.currentPhase = "Completado";
    state.completedAt = Date.now();
    this.notify(analysisId, state);
  }

  fail(analysisId: string, error: string) {
    const state = this.states.get(analysisId);
    if (!state) return;
    state.status = "failed";
    state.currentPhase = "Error";
    state.error = error;
    state.completedAt = Date.now();
    this.notify(analysisId, state);
  }

  subscribe(analysisId: string, listener: Listener): () => void {
    if (!this.listeners.has(analysisId)) {
      this.listeners.set(analysisId, new Set());
    }
    this.listeners.get(analysisId)!.add(listener);
    return () => {
      this.listeners.get(analysisId)?.delete(listener);
    };
  }

  private notify(analysisId: string, state: ScanProgressState) {
    const listeners = this.listeners.get(analysisId);
    if (listeners) {
      for (const listener of listeners) {
        listener({ ...state });
      }
    }
  }

  private recalculateProgress(state: ScanProgressState) {
    const activeSteps = state.steps.filter((s) => s.status !== "skipped");
    if (activeSteps.length === 0) return;
    const total = activeSteps.reduce((sum, s) => sum + s.progress, 0);
    state.overallProgress = Math.round(total / activeSteps.length);
    const running = activeSteps.find((s) => s.status === "running");
    if (running) state.currentPhase = running.label;
  }

  // Cleanup old states (keep last 20)
  cleanup() {
    if (this.states.size > 20) {
      const entries = [...this.states.entries()].sort(
        (a, b) => (a[1].startedAt || 0) - (b[1].startedAt || 0)
      );
      const toRemove = entries.slice(0, entries.length - 20);
      for (const [id] of toRemove) {
        this.states.delete(id);
        this.listeners.delete(id);
      }
    }
  }
}

// Singleton
export const scanProgressStore = new ScanProgressStore();

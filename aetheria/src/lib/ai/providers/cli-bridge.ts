import { execFile } from "child_process";
import type {
  AIProviderAdapter,
  AIProviderConfig,
  AIGenerateOptions,
  AIGenerateResponse,
  AIAvailableModel,
} from "./base";

const MAX_OUTPUT_BYTES = 1024 * 1024; // 1MB limit
const TIMEOUT_MS = 60_000; // 60 seconds

/**
 * CLI Bridge Adapter
 * Wraps local CLI tools (Grok CLI, Qoder CLI) as AI providers.
 * Spawns the binary with the prompt and captures structured output.
 *
 * Config: { binary: "grok" | "qoder", args?: string[] }
 */
export class CLIBridgeAdapter implements AIProviderAdapter {
  readonly type = "cli-bridge";

  constructor(private providerSlug?: string) {}

  private getBinary(config: AIProviderConfig): string {
    // Priority: explicit binaryPath > config.binary > slug-based default
    if (config.binaryPath) return config.binaryPath;
    if (config.config?.binary) return config.config.binary as string;
    if (this.providerSlug === "grok-cli") return "grok";
    if (this.providerSlug === "qoder-cli") return "qoder";
    return "grok"; // default
  }

  private getExtraArgs(config: AIProviderConfig): string[] {
    return (config.config?.args as string[]) || [];
  }

  private execute(binary: string, args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(
        binary,
        args,
        {
          timeout: TIMEOUT_MS,
          maxBuffer: MAX_OUTPUT_BYTES,
          env: { ...process.env },
        },
        (error, stdout, stderr) => {
          if (error) {
            const msg = stderr || error.message || "CLI execution failed";
            reject(new Error(`CLI error (${binary}): ${msg}`));
            return;
          }
          resolve(stdout);
        }
      );
    });
  }

  async generate(
    prompt: string,
    options: AIGenerateOptions,
    config: AIProviderConfig
  ): Promise<AIGenerateResponse> {
    const binary = this.getBinary(config);
    const extraArgs = this.getExtraArgs(config);

    // Build args based on the CLI tool
    let args: string[];
    if (binary.includes("grok")) {
      // Grok CLI: grok --model <model> --json "<prompt>"
      args = ["--json"];
      if (options.model) args.push("--model", options.model);
      args.push(...extraArgs, prompt);
    } else if (binary.includes("qoder")) {
      // Qoder CLI: qoder --prompt "<prompt>" --json
      args = ["--prompt", prompt, "--json"];
      if (options.model) args.push("--model", options.model);
      args.push(...extraArgs);
    } else {
      // Generic: binary --json "<prompt>"
      args = ["--json", ...extraArgs, prompt];
    }

    const stdout = await this.execute(binary, args);

    // Try to parse JSON output, fall back to raw text
    let text = stdout.trim();
    let inputTokens = 0;
    let outputTokens = 0;
    let modelUsed = options.model || "cli";

    try {
      const parsed = JSON.parse(stdout);
      text = parsed.response || parsed.text || parsed.content || parsed.result || stdout.trim();
      inputTokens = parsed.inputTokens || parsed.input_tokens || 0;
      outputTokens = parsed.outputTokens || parsed.output_tokens || 0;
      modelUsed = parsed.model || modelUsed;
    } catch {
      // Not JSON — use raw output as text
      // Estimate tokens (~4 chars per token)
      inputTokens = Math.ceil(prompt.length / 4);
      outputTokens = Math.ceil(text.length / 4);
    }

    return { text, inputTokens, outputTokens, modelUsed };
  }

  async listModels(config: AIProviderConfig): Promise<AIAvailableModel[]> {
    const binary = this.getBinary(config);

    if (binary.includes("grok")) {
      return [
        { modelId: "grok-3", displayName: "Grok 3 (CLI)" },
        { modelId: "grok-3-mini", displayName: "Grok 3 Mini (CLI)" },
        { modelId: "grok-3-fast", displayName: "Grok 3 Fast (CLI)" },
      ];
    }

    if (binary.includes("qoder")) {
      return [
        { modelId: "default", displayName: "Qoder Default (CLI)" },
      ];
    }

    return [{ modelId: "default", displayName: `${binary} (CLI)` }];
  }

  async testConnection(config: AIProviderConfig): Promise<{ ok: boolean; error?: string }> {
    const binary = this.getBinary(config);

    try {
      // Check if binary exists by running --version or --help
      const output = await this.execute(binary, ["--version"]);
      return { ok: true };
    } catch {
      // Try 'which' as fallback
      try {
        await this.execute("which", [binary]);
        return { ok: true };
      } catch {
        return {
          ok: false,
          error: `Binario "${binary}" no encontrado. Instálalo y asegúrate de que esté en el PATH.`,
        };
      }
    }
  }
}

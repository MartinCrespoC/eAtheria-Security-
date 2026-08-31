/**
 * Environment-variable fallbacks for AI provider API keys.
 *
 * If a provider has no encrypted key stored in the DB, the platform can
 * still run using a key provided via .env. Both the canonical
 * `<PROVIDER>_API_KEY` name and the short aliases the project has used
 * historically (OPEN_ROUTER, OPEN_AI) are accepted.
 */

const ENV_KEY_CANDIDATES: Record<string, string[]> = {
  gemini: ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
  openai: ["OPENAI_API_KEY", "OPEN_AI"],
  chatgpt: ["OPENAI_API_KEY", "OPEN_AI"],
  openrouter: ["OPENROUTER_API_KEY", "OPEN_ROUTER"],
  anthropic: ["ANTHROPIC_API_KEY", "ANTHROPIC_KEY"],
  deepseek: ["DEEPSEEK_API_KEY"],
  xai: ["XAI_API_KEY", "GROK_API_KEY"],
  mistral: ["MISTRAL_API_KEY"],
  nvidia: ["NVIDIA_API_KEY"],
  huggingface: ["HF_TOKEN", "HUGGINGFACE_API_KEY"],
  qwen: ["DASHSCOPE_API_KEY", "QWEN_API_KEY"],
  kimi: ["MOONSHOT_API_KEY", "KIMI_API_KEY"],
};

/**
 * Resolve an API key from the environment for the given provider slug.
 * Returns "" when nothing is configured.
 */
export function getEnvApiKey(slug: string): string {
  for (const envName of ENV_KEY_CANDIDATES[slug] || []) {
    const value = process.env[envName];
    if (value && value.trim()) return value.trim();
  }
  return "";
}

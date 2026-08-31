import type { AIProviderAdapter } from "./providers/base";
import { OpenAICompatAdapter } from "./providers/openai-compat";
import { GoogleGeminiAdapter } from "./providers/google-gemini";
import { AnthropicAdapter } from "./providers/anthropic";
import { AzureOpenAIAdapter } from "./providers/azure-openai";
import { AWSBedrockAdapter } from "./providers/aws-bedrock";
import { CopilotAdapter } from "./providers/copilot";
import { GoogleOAuthAdapter } from "./providers/google-oauth";
import { VertexAIAdapter } from "./providers/vertex-ai";
import { CLIBridgeAdapter } from "./providers/cli-bridge";

const adapterCache = new Map<string, AIProviderAdapter>();

export function getAdapter(providerType: string, providerSlug?: string): AIProviderAdapter {
  const cacheKey = `${providerType}:${providerSlug || ""}`;

  if (adapterCache.has(cacheKey)) {
    return adapterCache.get(cacheKey)!;
  }

  let adapter: AIProviderAdapter;

  switch (providerType) {
    case "google-gemini":
      adapter = new GoogleGeminiAdapter();
      break;
    case "google-gemini-oauth":
      adapter = new GoogleOAuthAdapter();
      break;
    case "anthropic":
      adapter = new AnthropicAdapter();
      break;
    case "azure-openai":
      adapter = new AzureOpenAIAdapter();
      break;
    case "aws-bedrock":
      adapter = new AWSBedrockAdapter();
      break;
    case "copilot":
      adapter = new CopilotAdapter();
      break;
    case "google-vertex":
      adapter = new VertexAIAdapter();
      break;
    case "cli-bridge":
      adapter = new CLIBridgeAdapter(providerSlug);
      break;
    case "openai-compatible":
    default:
      adapter = new OpenAICompatAdapter(providerSlug);
      break;
  }

  adapterCache.set(cacheKey, adapter);
  return adapter;
}

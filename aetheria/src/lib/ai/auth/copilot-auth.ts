import type { OAuthProviderConfig } from "./oauth-device";

// GitHub OAuth App for device code flow
// These are public client IDs — not secrets
const GITHUB_COPILOT_CLIENT_ID = "Iv1.b507a08c87ecfe98";

export const COPILOT_OAUTH_CONFIG: OAuthProviderConfig = {
  clientId: GITHUB_COPILOT_CLIENT_ID,
  deviceCodeUrl: "https://github.com/login/device/code",
  tokenUrl: "https://github.com/login/oauth/access_token",
  scope: "read:user",
  grantType: "urn:ietf:params:oauth:grant-type:device_code",
};

export async function getCopilotToken(githubToken: string): Promise<string> {
  // Exchange GitHub OAuth token for a Copilot session token
  const response = await fetch("https://api.github.com/copilot_internal/v2/token", {
    headers: {
      Authorization: `token ${githubToken}`,
      "Editor-Version": "vscode/1.104.1",
      "Editor-Plugin-Version": "copilot-chat/0.22.0",
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to get Copilot token: ${response.status}`);
  }

  const data = await response.json();
  return data.token;
}

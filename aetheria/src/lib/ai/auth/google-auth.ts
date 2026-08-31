import type { OAuthProviderConfig } from "./oauth-device";

// Google OAuth for Gemini CLI — public client ID (same as Gemini CLI uses)
const GOOGLE_GEMINI_CLI_CLIENT_ID = "936733106381-st8r0m12pbb2m2eo17h10qbguqhsvov3.apps.googleusercontent.com";

export const GOOGLE_OAUTH_CONFIG: OAuthProviderConfig = {
  clientId: GOOGLE_GEMINI_CLI_CLIENT_ID,
  deviceCodeUrl: "https://oauth2.googleapis.com/device/code",
  tokenUrl: "https://oauth2.googleapis.com/token",
  scope: "https://www.googleapis.com/auth/generative-language https://www.googleapis.com/auth/cloud-platform",
  grantType: "urn:ietf:params:oauth:grant-type:device_code",
};

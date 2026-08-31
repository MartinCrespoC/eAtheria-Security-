export interface DeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

export interface OAuthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  tokenType: string;
  scope?: string;
}

export interface OAuthProviderConfig {
  clientId: string;
  deviceCodeUrl: string;
  tokenUrl: string;
  scope: string;
  grantType?: string;
}

export async function startDeviceCodeFlow(
  providerConfig: OAuthProviderConfig
): Promise<DeviceCodeResponse> {
  const body = new URLSearchParams({
    client_id: providerConfig.clientId,
    scope: providerConfig.scope,
  });

  const response = await fetch(providerConfig.deviceCodeUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: body.toString(),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Device code request failed: ${response.status} — ${errText}`);
  }

  const data = await response.json();

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri: data.verification_uri || data.verification_url,
    expiresIn: data.expires_in || 900,
    interval: data.interval || 5,
  };
}

export async function pollForToken(
  providerConfig: OAuthProviderConfig,
  deviceCode: string
): Promise<OAuthTokenResponse | null> {
  const body = new URLSearchParams({
    client_id: providerConfig.clientId,
    device_code: deviceCode,
    grant_type: providerConfig.grantType || "urn:ietf:params:oauth:grant-type:device_code",
  });

  const response = await fetch(providerConfig.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: body.toString(),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const error = data.error || "";

    // authorization_pending = user hasn't authorized yet, keep polling
    if (error === "authorization_pending") return null;
    // slow_down = increase interval
    if (error === "slow_down") return null;
    // expired_token = device code expired
    if (error === "expired_token") throw new Error("Device code expired — restart flow");
    // access_denied = user denied
    if (error === "access_denied") throw new Error("User denied authorization");

    throw new Error(`Token poll failed: ${error || response.status}`);
  }

  const data = await response.json();

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in || 3600,
    tokenType: data.token_type || "Bearer",
    scope: data.scope,
  };
}

export async function refreshAccessToken(
  tokenUrl: string,
  clientId: string,
  refreshToken: string
): Promise<OAuthTokenResponse> {
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: body.toString(),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Token refresh failed: ${response.status} — ${errText}`);
  }

  const data = await response.json();

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || refreshToken,
    expiresIn: data.expires_in || 3600,
    tokenType: data.token_type || "Bearer",
    scope: data.scope,
  };
}

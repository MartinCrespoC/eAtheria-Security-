import crypto from "crypto";

export interface ParsedGithubEvent {
  type: string;
  action: string;
  repo: {
    id: number;
    fullName: string;
    name: string;
  };
  pr?: {
    number: number;
    headSha: string;
    headRef: string;
    baseRef: string;
    title: string;
  };
  branch?: string;
  sha?: string;
  sender?: {
    login: string;
    id: number;
  };
}

/**
 * Verify X-Hub-Signature-256 webhook signature
 */
export function verifySignature(payload: string, signature: string | null, secret: string): boolean {
  if (!signature || !secret) return false;

  const expected = "sha256=" + crypto
    .createHmac("sha256", secret)
    .update(payload, "utf-8")
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

/**
 * Parse GitHub webhook event from headers and body
 */
export function parseEvent(
  headers: Headers,
  body: Record<string, unknown>
): ParsedGithubEvent | null {
  const eventType = headers.get("x-github-event");
  if (!eventType) return null;

  const repo = body.repository as Record<string, unknown> | undefined;
  if (!repo) return null;

  const parsed: ParsedGithubEvent = {
    type: eventType,
    action: (body.action as string) || "",
    repo: {
      id: repo.id as number,
      fullName: repo.full_name as string,
      name: repo.name as string,
    },
  };

  const sender = body.sender as Record<string, unknown> | undefined;
  if (sender) {
    parsed.sender = {
      login: sender.login as string,
      id: sender.id as number,
    };
  }

  if (eventType === "pull_request") {
    const pr = body.pull_request as Record<string, unknown> | undefined;
    const head = pr?.head as Record<string, unknown> | undefined;
    const base = pr?.base as Record<string, unknown> | undefined;

    if (pr && head && base) {
      parsed.pr = {
        number: pr.number as number,
        headSha: head.sha as string,
        headRef: head.ref as string,
        baseRef: base.ref as string,
        title: pr.title as string,
      };
      parsed.branch = head.ref as string;
      parsed.sha = head.sha as string;
    }
  }

  if (eventType === "push") {
    const ref = body.ref as string;
    parsed.branch = ref?.replace("refs/heads/", "");
    parsed.sha = body.after as string;
  }

  return parsed;
}

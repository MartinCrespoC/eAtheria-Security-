export interface ParsedGitLabEvent {
  type: string;
  action: string;
  project: {
    id: number;
    name: string;
    pathWithNamespace: string;
    webUrl: string;
  };
  mr?: {
    iid: number;
    title: string;
    sourceBranch: string;
    targetBranch: string;
    sha: string;
  };
  branch?: string;
  sha?: string;
  user?: {
    username: string;
    name: string;
  };
}

/**
 * Verify X-Gitlab-Token header
 */
export function verifyToken(headers: Headers, expectedToken: string): boolean {
  if (!expectedToken) return false;
  const token = headers.get("x-gitlab-token");
  return token === expectedToken;
}

/**
 * Parse GitLab webhook event from headers and body
 */
export function parseEvent(
  headers: Headers,
  body: Record<string, unknown>
): ParsedGitLabEvent | null {
  const eventType = headers.get("x-gitlab-event");
  if (!eventType) return null;

  const project = body.project as Record<string, unknown> | undefined;
  if (!project) return null;

  const parsed: ParsedGitLabEvent = {
    type: eventType,
    action: (body.object_kind as string) || eventType,
    project: {
      id: project.id as number,
      name: project.name as string,
      pathWithNamespace: project.path_with_namespace as string,
      webUrl: project.web_url as string,
    },
  };

  const user = body.user as Record<string, unknown> | undefined;
  if (user) {
    parsed.user = {
      username: user.username as string,
      name: user.name as string,
    };
  }

  // Merge Request event
  if (eventType === "Merge Request Hook" || body.object_kind === "merge_request") {
    const attrs = body.object_attributes as Record<string, unknown> | undefined;
    if (attrs) {
      parsed.mr = {
        iid: attrs.iid as number,
        title: attrs.title as string,
        sourceBranch: attrs.source_branch as string,
        targetBranch: attrs.target_branch as string,
        sha: attrs.last_commit?.toString() || (attrs.sha as string),
      };
      parsed.branch = attrs.source_branch as string;

      // Extract SHA from last_commit object
      const lastCommit = attrs.last_commit as Record<string, unknown> | undefined;
      if (lastCommit) {
        parsed.sha = lastCommit.id as string;
        parsed.mr.sha = lastCommit.id as string;
      }
    }
  }

  // Push event
  if (eventType === "Push Hook" || body.object_kind === "push") {
    const ref = body.ref as string;
    parsed.branch = ref?.replace("refs/heads/", "");
    parsed.sha = body.after as string;
  }

  return parsed;
}

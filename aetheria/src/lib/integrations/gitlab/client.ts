/**
 * GitLab REST API client with PAT authentication.
 */
export class GitLabClient {
  private baseUrl: string;
  private token: string;

  constructor(projectUrl: string, accessToken: string) {
    // Extract base URL from project URL (e.g., https://gitlab.com/group/project -> https://gitlab.com)
    try {
      const url = new URL(projectUrl);
      this.baseUrl = `${url.protocol}//${url.host}`;
    } catch {
      this.baseUrl = "https://gitlab.com";
    }
    this.token = accessToken;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}/api/v4${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "PRIVATE-TOKEN": this.token,
        "Content-Type": "application/json",
        ...options.headers,
      },
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`GitLab API error ${response.status}: ${text}`);
    }

    return response.json() as Promise<T>;
  }

  /**
   * List projects accessible to the token
   */
  async listProjects(params: { search?: string; perPage?: number } = {}): Promise<GitLabProject[]> {
    const search = params.search ? `&search=${encodeURIComponent(params.search)}` : "";
    const perPage = params.perPage || 20;
    return this.request<GitLabProject[]>(`/projects?membership=true&per_page=${perPage}${search}`);
  }

  /**
   * Get a specific merge request
   */
  async getMergeRequest(projectId: string, mrIid: number): Promise<GitLabMergeRequest> {
    const encodedId = encodeURIComponent(projectId);
    return this.request<GitLabMergeRequest>(`/projects/${encodedId}/merge_requests/${mrIid}`);
  }

  /**
   * Post a comment (note) on a merge request
   */
  async postComment(projectId: string, mrIid: number, body: string): Promise<void> {
    const encodedId = encodeURIComponent(projectId);
    await this.request(`/projects/${encodedId}/merge_requests/${mrIid}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    });
  }

  /**
   * Get a file from the repository
   */
  async getFile(projectId: string, filePath: string, ref: string): Promise<{ content: string }> {
    const encodedId = encodeURIComponent(projectId);
    const encodedPath = encodeURIComponent(filePath);
    return this.request<{ content: string }>(`/projects/${encodedId}/repository/files/${encodedPath}?ref=${ref}`);
  }

  /**
   * Get repository tree (file listing)
   */
  async getTree(projectId: string, ref: string, path?: string): Promise<Array<{ name: string; path: string; type: string }>> {
    const encodedId = encodeURIComponent(projectId);
    const pathParam = path ? `&path=${encodeURIComponent(path)}` : "";
    return this.request(`/projects/${encodedId}/repository/tree?ref=${ref}&recursive=true&per_page=100${pathParam}`);
  }
}

export interface GitLabProject {
  id: number;
  name: string;
  path_with_namespace: string;
  web_url: string;
  default_branch: string;
  description: string | null;
}

export interface GitLabMergeRequest {
  iid: number;
  title: string;
  state: string;
  source_branch: string;
  target_branch: string;
  sha: string;
  web_url: string;
  author: { username: string; name: string };
}

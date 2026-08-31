/**
 * GitLab Integration Module — Barrel Export
 *
 * Centralizes GitLab-related exports:
 * - MR scanner (triggers security scans on merge requests)
 * - MR commenter (posts scan results as MR comments)
 * - Webhook handler (parses & verifies GitLab webhook events)
 * - GitLab API client
 */

// GitLab API client
export { GitLabClient } from "./client";
export type { GitLabProject, GitLabMergeRequest } from "./client";

// MR scanner
export { triggerMRScan } from "./mr-scanner";

// MR commenter
export { postScanResults } from "./mr-commenter";

// Webhook handler
export { verifyToken, parseEvent } from "./webhook-handler";
export type { ParsedGitLabEvent } from "./webhook-handler";

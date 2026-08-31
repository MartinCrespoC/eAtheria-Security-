/**
 * GitHub Integration Module — Barrel Export
 *
 * Centralizes GitHub-related exports:
 * - PR scanner (triggers security scans on pull requests)
 * - PR commenter (posts scan results as PR comments)
 * - Webhook handler (parses & verifies GitHub webhook events)
 */

// PR scanner
export { triggerPRScan } from "./pr-scanner";

// PR commenter
export { postScanResults } from "./pr-commenter";

// Webhook handler
export { verifySignature, parseEvent } from "./webhook-handler";
export type { ParsedGithubEvent } from "./webhook-handler";

/**
 * IDOR (Insecure Direct Object Reference) Protection
 * Prevents unauthorized access to resources by validating ownership
 */

import { prisma } from "@/lib/db";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";

export class IDORError extends Error {
  constructor(message: string = "Unauthorized access to resource") {
    super(message);
    this.name = "IDORError";
  }
}

/**
 * Verify that a resource belongs to the authenticated user's company
 * Throws IDORError if validation fails
 */
export async function verifyResourceOwnership(
  resourceType: string,
  resourceId: string,
  userId?: string,
  companyId?: string
): Promise<void> {
  // Get session if not provided
  if (!userId || !companyId) {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      throw new IDORError("Not authenticated");
    }
    userId = session.user.id;
    companyId = session.user.companyId || undefined;
  }

  // System admins can access all resources
  const session = await getServerSession(authOptions);
  if (session?.user?.isSystemAdmin) {
    return;
  }

  // Verify ownership based on resource type
  switch (resourceType) {
    case "analysis":
      await verifyAnalysisOwnership(resourceId, companyId!);
      break;
    case "application":
      await verifyApplicationOwnership(resourceId, companyId!);
      break;
    case "apiKey":
      await verifyApiKeyOwnership(resourceId, userId);
      break;
    case "githubConnection":
      await verifyGithubConnectionOwnership(resourceId, companyId!);
      break;
    case "user":
      await verifyUserOwnership(resourceId, companyId!);
      break;
    default:
      throw new IDORError(`Unknown resource type: ${resourceType}`);
  }
}

async function verifyAnalysisOwnership(analysisId: string, companyId: string): Promise<void> {
  const analysis = await prisma.analysis.findUnique({
    where: { id: analysisId },
    select: {
      appVersion: {
        select: {
          application: {
            select: { companyId: true },
          },
        },
      },
    },
  });

  if (!analysis) {
    throw new IDORError("Analysis not found");
  }

  if (analysis.appVersion.application.companyId !== companyId) {
    throw new IDORError("Unauthorized access to analysis");
  }
}

async function verifyApplicationOwnership(applicationId: string, companyId: string): Promise<void> {
  const application = await prisma.application.findUnique({
    where: { id: applicationId },
    select: { companyId: true },
  });

  if (!application) {
    throw new IDORError("Application not found");
  }

  if (application.companyId !== companyId) {
    throw new IDORError("Unauthorized access to application");
  }
}

async function verifyApiKeyOwnership(apiKeyId: string, userId: string): Promise<void> {
  const apiKey = await prisma.apiKey.findUnique({
    where: { id: apiKeyId },
    select: { createdById: true },
  });

  if (!apiKey) {
    throw new IDORError("API key not found");
  }

  if (apiKey.createdById !== userId) {
    throw new IDORError("Unauthorized access to API key");
  }
}

async function verifyGithubConnectionOwnership(
  connectionId: string,
  companyId: string
): Promise<void> {
  const connection = await prisma.githubConnection.findUnique({
    where: { id: connectionId },
    select: { companyId: true },
  });

  if (!connection) {
    throw new IDORError("GitHub connection not found");
  }

  if (connection.companyId !== companyId) {
    throw new IDORError("Unauthorized access to GitHub connection");
  }
}

async function verifyUserOwnership(targetUserId: string, companyId: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: targetUserId },
    select: { companyId: true },
  });

  if (!user) {
    throw new IDORError("User not found");
  }

  if (user.companyId !== companyId) {
    throw new IDORError("Unauthorized access to user");
  }
}

/**
 * Middleware helper to validate resource ownership in API routes
 */
export async function requireResourceOwnership(
  resourceType: string,
  resourceId: string
): Promise<{ userId: string; companyId: string | null }> {
  const session = await getServerSession(authOptions);

  if (!session?.user) {
    throw new IDORError("Not authenticated");
  }

  await verifyResourceOwnership(
    resourceType,
    resourceId,
    session.user.id,
    session.user.companyId || undefined
  );

  return {
    userId: session.user.id,
    companyId: session.user.companyId || null,
  };
}

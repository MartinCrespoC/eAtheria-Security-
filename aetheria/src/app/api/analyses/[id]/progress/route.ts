import { NextRequest } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { scanProgressStore } from "@/lib/analysis/scan-progress";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await auth();
  if (!session?.user?.companyId) {
    return new Response(JSON.stringify({ error: "No autorizado" }), { status: 401 });
  }

  const { id } = await params;

  // Verify ownership
  const analysis = await prisma.analysis.findFirst({
    where: { id, appVersion: { application: { companyId: session.user.companyId } } },
    select: { id: true, status: true },
  });

  if (!analysis) {
    return new Response(JSON.stringify({ error: "Análisis no encontrado" }), { status: 404 });
  }

  // If analysis already completed/failed, return final state immediately
  if (["COMPLETED", "FAILED"].includes(analysis.status)) {
    const state = scanProgressStore.getState(id);
    return new Response(JSON.stringify(state || { status: analysis.status.toLowerCase(), overallProgress: 100 }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // SSE stream for in-progress analysis
  const encoder = new TextEncoder();
  let lastSent = "";

  const stream = new ReadableStream({
    start(controller) {
      const send = (data: unknown) => {
        const json = JSON.stringify(data);
        if (json !== lastSent) {
          lastSent = json;
          controller.enqueue(encoder.encode(`data: ${json}\n\n`));
        }
      };

      // Send current state immediately
      const currentState = scanProgressStore.getState(id);
      if (currentState) {
        send(currentState);
      } else {
        send({ status: "queued", overallProgress: 0, currentPhase: "En cola", scanLevel: "STATIC", scanTypes: ["SAST"], steps: [], logs: [], stats: { filesDiscovered: 0, filesAnalyzed: 0, languagesDetected: [], dependenciesFound: 0, vulnerabilitiesFound: 0, falsePositivesDetected: 0, linesOfCode: 0 }, startedAt: Date.now() });
      }

      // Subscribe to updates
      const unsubscribe = scanProgressStore.subscribe(id, (state) => {
        try {
          send(state);
          // Close stream when done
          if (state.status === "completed" || state.status === "failed") {
            setTimeout(() => {
              unsubscribe();
              controller.close();
            }, 1000);
          }
        } catch {
          unsubscribe();
        }
      });

      // Heartbeat every 15s to keep connection alive
      const heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(`: heartbeat\n\n`));
        } catch {
          clearInterval(heartbeat);
          unsubscribe();
        }
      }, 15000);

      // Cleanup on abort
      request.signal.addEventListener("abort", () => {
        clearInterval(heartbeat);
        unsubscribe();
        try { controller.close(); } catch { /* already closed */ }
      });

      // Safety timeout: close after 10 minutes
      setTimeout(() => {
        clearInterval(heartbeat);
        unsubscribe();
        try { controller.close(); } catch { /* already closed */ }
      }, 600000);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

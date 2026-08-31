import { NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";

interface GoogleModel {
  name: string;
  displayName: string;
  description: string;
  inputTokenLimit: number;
  outputTokenLimit: number;
  supportedGenerationMethods: string[];
}

// GET — list available models from Google Generative AI API
export async function GET() {
  try {
    await requireSystemAdmin();

    const apiKey = process.env.GOOGLE_API_KEY;
    if (!apiKey) {
      return NextResponse.json(
        { error: "GOOGLE_API_KEY no configurado" },
        { status: 500 }
      );
    }

    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}&pageSize=100`,
      { next: { revalidate: 300 } } // cache 5 min
    );

    if (!res.ok) {
      const errText = await res.text();
      console.error("Google API error:", errText);
      return NextResponse.json(
        { error: "Error al consultar Google API", details: errText },
        { status: res.status }
      );
    }

    const data = await res.json();
    const googleModels: GoogleModel[] = data.models || [];

    // Filter to only models that support generateContent
    const generativeModels = googleModels.filter((m) =>
      m.supportedGenerationMethods?.includes("generateContent")
    );

    // Get models already in our DB
    const existingModels = await prisma.aIModel.findMany({
      select: { modelId: true },
    });
    const existingIds = new Set(existingModels.map((m) => m.modelId));

    // Map to clean format
    const available = generativeModels.map((m) => {
      // name comes as "models/gemini-2.5-flash" → extract id
      const modelId = m.name.replace("models/", "");
      return {
        modelId,
        displayName: m.displayName || modelId,
        description: m.description || "",
        inputTokenLimit: m.inputTokenLimit || 0,
        outputTokenLimit: m.outputTokenLimit || 0,
        alreadyAdded: existingIds.has(modelId),
      };
    });

    // Sort: not-added first, then by name
    available.sort((a, b) => {
      if (a.alreadyAdded !== b.alreadyAdded) return a.alreadyAdded ? 1 : -1;
      return a.displayName.localeCompare(b.displayName);
    });

    return NextResponse.json(available);
  } catch (error) {
    if (error instanceof Error && error.message === "UNAUTHORIZED")
      return NextResponse.json({ error: "No autorizado" }, { status: 401 });
    if (error instanceof Error && error.message === "FORBIDDEN")
      return NextResponse.json({ error: "Acceso denegado" }, { status: 403 });
    console.error("Error fetching available models:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from "next/server";
import { requireSystemAdmin } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { writeFile, mkdir } from "fs/promises";
import { join } from "path";

const MAX_SIZE = 2 * 1024 * 1024; // 2MB
const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/svg+xml", "image/webp", "image/x-icon"];

export async function POST(request: NextRequest) {
  try {
    await requireSystemAdmin();

    const formData = await request.formData();
    const file = formData.get("file") as File | null;
    const type = formData.get("type") as string | null; // "logo" | "favicon"

    if (!file) {
      return NextResponse.json({ error: "Archivo requerido" }, { status: 400 });
    }

    if (!ALLOWED_TYPES.includes(file.type)) {
      return NextResponse.json(
        { error: "Tipo de archivo no permitido. Use PNG, JPG, SVG, WebP o ICO." },
        { status: 400 }
      );
    }

    if (file.size > MAX_SIZE) {
      return NextResponse.json(
        { error: "El archivo no debe superar 2MB" },
        { status: 400 }
      );
    }

    const uploadType = type === "favicon" ? "favicon" : "logo";
    const ext = file.name.split(".").pop() || "png";
    const fileName = `${uploadType}.${ext}`;

    // Save to public directory
    const uploadDir = join(process.cwd(), "public", "branding");
    await mkdir(uploadDir, { recursive: true });

    const filePath = join(uploadDir, fileName);
    const bytes = await file.arrayBuffer();
    await writeFile(filePath, Buffer.from(bytes));

    const publicUrl = `/branding/${fileName}`;

    // Store URL in system config
    await prisma.systemConfig.upsert({
      where: { key: `branding_${uploadType}` },
      update: { value: publicUrl },
      create: { key: `branding_${uploadType}`, value: publicUrl },
    });

    return NextResponse.json({
      success: true,
      url: publicUrl,
      type: uploadType,
    });
  } catch (error) {
    console.error("Upload logo error:", error);
    return NextResponse.json({ error: "Error interno" }, { status: 500 });
  }
}

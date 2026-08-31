import { prisma } from "@/lib/db";
import { CweCatalogList } from "@/components/dashboard/cwe-catalog-list";

export default async function CatalogPage() {
  const catalog = await prisma.vulnerabilityCatalog.findMany({
    orderBy: { cweId: "asc" },
    take: 200,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Catálogo CWE</h1>
        <p className="text-text-secondary mt-1">
          Referencia de debilidades comunes de seguridad (CWE)
        </p>
      </div>
      <CweCatalogList catalog={catalog} />
    </div>
  );
}

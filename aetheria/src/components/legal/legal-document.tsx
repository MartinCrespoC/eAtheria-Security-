import type { LegalDoc } from "@/lib/legal-content";

export function LegalDocument({ doc }: { doc: LegalDoc }) {
  return (
    <article>
      <h1 className="text-2xl md:text-3xl font-black text-white mb-2">
        {doc.title}
      </h1>
      <p className="text-xs text-slate-500 mb-6">{doc.updated}</p>
      <p className="text-sm text-slate-300 leading-relaxed mb-8 p-4 rounded-xl bg-cyan-500/5 border border-cyan-500/20">
        {doc.intro}
      </p>
      <div className="space-y-8">
        {doc.sections.map((section) => (
          <section key={section.heading}>
            <h2 className="text-base font-bold text-cyan-300 mb-3">
              {section.heading}
            </h2>
            <div className="space-y-3">
              {section.body.map((paragraph, i) => (
                <p
                  key={i}
                  className="text-sm text-slate-400 leading-relaxed"
                >
                  {paragraph}
                </p>
              ))}
            </div>
          </section>
        ))}
      </div>
    </article>
  );
}

"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Search, BookOpen, ChevronRight } from "lucide-react";
import { DOCUMENTATION_SECTIONS, searchDocumentation, type DocumentationSection } from "@/lib/documentation/content";

export function DocumentationViewer() {
  const [selectedSection, setSelectedSection] = useState<DocumentationSection>(DOCUMENTATION_SECTIONS[0]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<DocumentationSection[]>([]);

  const handleSearch = (query: string) => {
    setSearchQuery(query);
    if (query.trim().length > 2) {
      const results = searchDocumentation(query);
      setSearchResults(results);
    } else {
      setSearchResults([]);
    }
  };

  const categories = {
    architecture: "Arquitectura",
    usage: "Guías de Uso",
    troubleshooting: "Troubleshooting",
    api: "API Reference",
    security: "Seguridad",
    deployment: "Deployment",
  };

  const sectionsToShow = searchQuery.trim().length > 2 ? searchResults : DOCUMENTATION_SECTIONS;

  return (
    <div className="grid grid-cols-12 gap-6 h-[calc(100vh-12rem)]">
      {/* Sidebar */}
      <div className="col-span-3 bg-slate-800 rounded-lg border border-slate-700 p-4 overflow-y-auto">
        <div className="mb-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              placeholder="Buscar en docs..."
              className="w-full bg-slate-900 text-white pl-10 pr-4 py-2 rounded-lg border border-slate-700 focus:border-cyan-400 focus:outline-none text-sm"
            />
          </div>
        </div>

        <nav className="space-y-1">
          {sectionsToShow.map((section) => (
            <button
              key={section.id}
              onClick={() => {
                setSelectedSection(section);
                setSearchQuery("");
                setSearchResults([]);
              }}
              className={`w-full text-left px-3 py-2 rounded-lg transition-colors flex items-start gap-2 ${
                selectedSection.id === section.id
                  ? "bg-cyan-500/20 text-cyan-400 border border-cyan-400/30"
                  : "text-slate-300 hover:bg-slate-700"
              }`}
            >
              <span className="text-lg mt-0.5">{section.icon}</span>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm truncate">{section.title}</div>
                <div className="text-xs text-slate-400 truncate">{section.description}</div>
              </div>
              {selectedSection.id === section.id && (
                <ChevronRight className="w-4 h-4 mt-1 flex-shrink-0" />
              )}
            </button>
          ))}
        </nav>

        {searchQuery.trim().length > 2 && searchResults.length === 0 && (
          <div className="text-center py-8 text-slate-400 text-sm">
            No se encontraron resultados
          </div>
        )}
      </div>

      {/* Content */}
      <div className="col-span-9 bg-slate-800 rounded-lg border border-slate-700 p-6 overflow-y-auto">
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-3xl">{selectedSection.icon}</span>
            <div>
              <h1 className="text-2xl font-bold text-white">{selectedSection.title}</h1>
              <p className="text-slate-400">{selectedSection.description}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
              {categories[selectedSection.category]}
            </span>
            {selectedSection.tags.map((tag) => (
              <span key={tag} className="px-2 py-1 bg-slate-700 text-slate-300 text-xs rounded">
                {tag}
              </span>
            ))}
            <span className="ml-auto text-xs text-slate-500">
              Actualizado: {selectedSection.lastUpdated}
            </span>
          </div>
        </div>

        <div className="prose prose-invert prose-slate max-w-none">
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              h1: ({ children }) => (
                <h1 className="text-3xl font-bold text-white mt-8 mb-4 border-b border-slate-700 pb-2">
                  {children}
                </h1>
              ),
              h2: ({ children }) => (
                <h2 className="text-2xl font-bold text-white mt-6 mb-3">{children}</h2>
              ),
              h3: ({ children }) => (
                <h3 className="text-xl font-semibold text-cyan-400 mt-4 mb-2">{children}</h3>
              ),
              p: ({ children }) => <p className="text-slate-300 mb-4 leading-relaxed">{children}</p>,
              ul: ({ children }) => <ul className="list-disc list-inside text-slate-300 mb-4 space-y-1">{children}</ul>,
              ol: ({ children }) => <ol className="list-decimal list-inside text-slate-300 mb-4 space-y-1">{children}</ol>,
              li: ({ children }) => <li className="ml-4">{children}</li>,
              code: ({ inline, children }: any) =>
                inline ? (
                  <code className="bg-slate-900 text-cyan-400 px-1.5 py-0.5 rounded text-sm font-mono">
                    {children}
                  </code>
                ) : (
                  <code className="block bg-slate-900 text-cyan-400 p-4 rounded-lg overflow-x-auto text-sm font-mono mb-4">
                    {children}
                  </code>
                ),
              pre: ({ children }) => <pre className="mb-4">{children}</pre>,
              a: ({ href, children }) => (
                <a href={href} className="text-cyan-400 hover:text-cyan-300 underline" target="_blank" rel="noopener noreferrer">
                  {children}
                </a>
              ),
              blockquote: ({ children }) => (
                <blockquote className="border-l-4 border-cyan-400 pl-4 italic text-slate-400 my-4">
                  {children}
                </blockquote>
              ),
              table: ({ children }) => (
                <div className="overflow-x-auto mb-4">
                  <table className="min-w-full divide-y divide-slate-700">{children}</table>
                </div>
              ),
              th: ({ children }) => (
                <th className="px-4 py-2 bg-slate-900 text-left text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  {children}
                </th>
              ),
              td: ({ children }) => (
                <td className="px-4 py-2 text-sm text-slate-300 border-t border-slate-700">
                  {children}
                </td>
              ),
            }}
          >
            {selectedSection.content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}

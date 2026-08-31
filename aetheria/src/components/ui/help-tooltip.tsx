"use client";

import { useState } from "react";
import { HelpCircle, X } from "lucide-react";

interface HelpTooltipProps {
  title: string;
  shortHelp: string;
  detailedHelp: string;
  examples?: string[];
}

export function HelpTooltip({ title, shortHelp, detailedHelp, examples }: HelpTooltipProps) {
  const [showModal, setShowModal] = useState(false);
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <>
      {/* Help Icon */}
      <div className="relative inline-block">
        <button
          onMouseEnter={() => setShowTooltip(true)}
          onMouseLeave={() => setShowTooltip(false)}
          onClick={() => setShowModal(true)}
          className="text-text-secondary hover:text-accent transition-colors ml-2"
          aria-label="Ayuda"
        >
          <HelpCircle className="w-4 h-4" />
        </button>

        {/* Tooltip on Hover */}
        {showTooltip && !showModal && (
          <div className="absolute z-50 bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-surface text-text-primary text-sm rounded-lg shadow-lg border border-border whitespace-nowrap max-w-xs">
            {shortHelp}
            <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
              <div className="border-4 border-transparent border-t-slate-800" />
            </div>
          </div>
        )}
      </div>

      {/* Detailed Modal on Click */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface rounded-lg border border-border max-w-2xl w-full max-h-[80vh] overflow-hidden shadow-2xl">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-cyan-500/20 rounded-lg">
                  <HelpCircle className="w-6 h-6 text-accent" />
                </div>
                <h2 className="text-2xl font-bold text-text-primary">{title}</h2>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-text-secondary hover:text-text-primary transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto max-h-[calc(80vh-120px)]">
              <div className="space-y-4">
                {/* Short Help */}
                <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
                  <p className="text-accent font-medium">{shortHelp}</p>
                </div>

                {/* Detailed Help */}
                <div className="text-text-primary space-y-3">
                  {detailedHelp.split('\n\n').map((paragraph, i) => (
                    <p key={i} className="leading-relaxed">{paragraph}</p>
                  ))}
                </div>

                {/* Examples */}
                {examples && examples.length > 0 && (
                  <div className="mt-6">
                    <h3 className="text-lg font-semibold text-text-primary mb-3">📝 Ejemplos:</h3>
                    <div className="space-y-2">
                      {examples.map((example, i) => (
                        <div key={i} className="p-3 bg-card rounded-lg border border-border">
                          <code className="text-sm text-accent">{example}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-border bg-card">
              <button
                onClick={() => setShowModal(false)}
                className="w-full bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded-lg font-semibold transition-colors"
              >
                Entendido
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

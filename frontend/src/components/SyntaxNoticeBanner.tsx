'use client';

import React from 'react';
import { AlertCircle, HelpCircle, X, Terminal } from 'lucide-react';

interface SyntaxNoticeBannerProps {
  title?: string;
  message: string;
  recommendation?: string;
  onDismiss: () => void;
}

export function SyntaxNoticeBanner({
  title = 'INVALID INPUT SYNTAX',
  message,
  recommendation = 'Please ensure your input contains a valid top-level domain or network protocol.',
  onDismiss,
}: SyntaxNoticeBannerProps) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className="w-full rounded-2xl border border-zinc-800 bg-zinc-900/90 p-5 sm:p-6 backdrop-blur-xl shadow-2xl transition-all"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-zinc-800/80 border border-zinc-700/60 flex items-center justify-center text-zinc-300 shrink-0 mt-0.5 shadow-inner">
            <AlertCircle className="w-5 h-5 text-amber-400" />
          </div>

          <div className="space-y-1.5 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h3 className="text-base sm:text-lg font-bold font-mono text-zinc-100 tracking-tight">
                {title}
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border border-zinc-700/70 bg-zinc-800/60 text-zinc-400">
                HTTP 400 &bull; GATEWAY REJECTION
              </span>
            </div>

            <p className="text-sm font-sans text-zinc-300 leading-relaxed max-w-2xl">
              {message}
            </p>

            <div className="mt-3 p-3 rounded-lg bg-zinc-950/70 border border-zinc-800/90 flex items-start gap-2.5 text-xs font-mono text-zinc-400">
              <Terminal className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="text-zinc-300 font-semibold">Recommendation: </span>
                <span>{recommendation}</span>
              </div>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={onDismiss}
          className="p-1 rounded-lg text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60 transition-colors"
          title="Dismiss notification"
          aria-label="Dismiss notification"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

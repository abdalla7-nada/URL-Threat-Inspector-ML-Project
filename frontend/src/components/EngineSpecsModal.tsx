'use client';

import React from 'react';
import { Server, ShieldCheck, Layers, Terminal, CheckCircle2 } from 'lucide-react';

interface EngineSpecsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function EngineSpecsModal({ isOpen, onClose }: EngineSpecsModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-2xl bg-zinc-900 border border-zinc-800 shadow-2xl p-6 sm:p-8 font-mono">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-zinc-850 border border-zinc-750 flex items-center justify-center text-emerald-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-zinc-100">
                CLASSIFIER ENGINE SPECIFICATIONS
              </h2>
              <p className="text-xs text-zinc-400 font-sans">
                Deterministic threat assessment architecture & validation benchmarks
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            type="button"
            className="px-2.5 py-1 rounded-lg text-xs font-mono text-zinc-400 hover:text-zinc-200 bg-zinc-800 hover:bg-zinc-700 transition-colors"
          >
            Close [ESC]
          </button>
        </div>

        {/* Specifications Matrix */}
        <div className="mt-6 space-y-4 text-xs">
          <div className="p-4 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
            <div className="text-zinc-400 uppercase tracking-wider mb-2 text-[11px] font-semibold text-emerald-400 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              <span>Model Architecture & Pipeline</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-zinc-300">
              <div>
                <span className="text-zinc-500">Algorithm:</span> LightGBM Gradient Boosted Tree
              </div>
              <div>
                <span className="text-zinc-500">Estimators:</span> 300 Trees (lr=0.05, leaves=31)
              </div>
              <div>
                <span className="text-zinc-500">Feature Count:</span> 29 Lexical & Structural Metrics
              </div>
              <div>
                <span className="text-zinc-500">Categorical TLDs:</span> Top 50 Frequent + Other
              </div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
            <div className="text-zinc-400 uppercase tracking-wider mb-2 text-[11px] font-semibold text-emerald-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5" />
              <span>Validation & Generalization Methodology</span>
            </div>
            <div className="space-y-1 text-zinc-300">
              <div>
                <span className="text-zinc-500">Split Method:</span> StratifiedGroupKFold (5 Folds, Seed=42)
              </div>
              <div>
                <span className="text-zinc-500">Grouping Strategy:</span> Registrable domain (PSL), 153,901 groups
              </div>
              <div className="text-emerald-400/90 flex items-center gap-1 mt-1 text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                <span>Zero domain overlap between train and test splits (no leakage).</span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
            <div className="text-zinc-400 uppercase tracking-wider mb-2 text-[11px] font-semibold text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Calibrated Operational Benchmarks (Test Split: 103,037 URLs)</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-zinc-200">
              <div className="p-2.5 rounded-lg bg-zinc-900 border border-zinc-800">
                <div className="text-[10px] text-zinc-500 uppercase">ROC-AUC</div>
                <div className="text-base font-bold text-zinc-100">0.9344</div>
              </div>
              <div className="p-2.5 rounded-lg bg-zinc-900 border border-zinc-800">
                <div className="text-[10px] text-zinc-500 uppercase">Target FPR</div>
                <div className="text-base font-bold text-emerald-400">&le; 5.00%</div>
              </div>
              <div className="p-2.5 rounded-lg bg-zinc-900 border border-zinc-800">
                <div className="text-[10px] text-zinc-500 uppercase">Phish Recall</div>
                <div className="text-base font-bold text-zinc-100">65.80%</div>
              </div>
              <div className="p-2.5 rounded-lg bg-zinc-900 border border-zinc-800">
                <div className="text-[10px] text-zinc-500 uppercase">Accuracy</div>
                <div className="text-base font-bold text-zinc-100">89.93%</div>
              </div>
            </div>
            <div className="mt-2 text-[11px] text-zinc-400">
              Calibrated Threshold: <span className="text-zinc-200 font-bold">0.4705</span> (optimizes recall subject to strict FPR constraint)
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-zinc-800 flex justify-end">
          <button
            onClick={onClose}
            type="button"
            className="px-4 py-2 rounded-lg text-xs font-mono font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}

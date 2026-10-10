'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Terminal,
  Activity,
  Server,
  ExternalLink,
} from 'lucide-react';

interface HeaderProps {
  onOpenSpecs?: () => void;
  latency?: number | null;
}

export function Header({ onOpenSpecs, latency }: HeaderProps) {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  return (
    <header className="w-full border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Identification */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center text-emerald-400 shadow-inner">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-zinc-100 tracking-wider text-sm sm:text-base font-mono">
                CYBERSEC URL INSPECTOR
              </span>
              <span className="hidden md:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-zinc-800/80 text-zinc-300 border border-zinc-700/60">
                PROD v1.0
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 font-mono hidden sm:block">
              Deterministic Lexical & Gradient Boost Engine
            </p>
          </div>
        </div>

        {/* System Telemetry & External Controls */}
        <div className="flex items-center gap-3 sm:gap-4">
          {/* Policy Compliance Badge */}
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-md bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-300">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span>POLICY: FPR &le; 5.0%</span>
          </div>

          {/* Real-time Latency Telemetry */}
          {isMounted && latency !== null && latency !== undefined && (
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-400">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>{latency.toFixed(1)}ms</span>
            </div>
          )}

          {/* Engine Specs Trigger */}
          {onOpenSpecs && (
            <button
              onClick={onOpenSpecs}
              type="button"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 hover:border-zinc-700 transition-colors"
            >
              <Server className="w-3.5 h-3.5 text-zinc-400" />
              <span className="hidden sm:inline">Engine Specs</span>
            </button>
          )}

          {/* Direct API Documentation Link */}
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 hover:border-zinc-700 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5 text-zinc-400" />
            <span className="hidden sm:inline">API Docs</span>
            <ExternalLink className="w-3 h-3 text-zinc-500" />
          </a>
        </div>
      </div>
    </header>
  );
}

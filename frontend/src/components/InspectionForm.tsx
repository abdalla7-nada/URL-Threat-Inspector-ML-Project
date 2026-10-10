'use client';

import React, { useState } from 'react';
import { Search, Terminal, ArrowUpRight, Activity, Info } from 'lucide-react';

interface InspectionFormProps {
  onInspect: (url: string) => Promise<void>;
  isLoading: boolean;
}

const PRESET_TARGETS = [
  {
    label: 'Safe Enterprise',
    url: 'https://www.wikipedia.org/wiki/Computer_security',
    tag: 'BENIGN',
  },
  {
    label: 'Raw IP Host',
    url: 'http://192.168.1.1/login-admin-verify-password',
    tag: 'MALICIOUS',
  },
  {
    label: 'Phishing Lure',
    url: 'https://secure-login-verify-account.example.com/update',
    tag: 'SUSPICIOUS',
  },
  {
    label: 'Punycode Host',
    url: 'https://xn--bcher-kva.com/auth-signin',
    tag: 'PUNYCODE',
  },
];

export function InspectionForm({ onInspect, isLoading }: InspectionFormProps) {
  const [inputUrl, setInputUrl] = useState('');
  const isSubmittingRef = React.useRef<boolean>(false);
  const lastSubmitTimeRef = React.useRef<number>(0);

  // Input Sanitization: Strip zero-width chars and trailing dots/whitespace
  const sanitizeUrl = (raw: string): string => {
    const stripped = raw.replace(/[\u200B-\u200D\uFEFF]/g, '');
    return stripped.trim().replace(/\.+$/, '');
  };

  const trimmed = inputUrl.trim();
  const isPlainWordsWithoutDomain =
    trimmed.length > 0 && !trimmed.includes('.') && !trimmed.includes('/');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const now = Date.now();

    // Double-click & rapid debounce guard: reject if already loading, submitting, or < 500ms
    if (isLoading || isSubmittingRef.current || now - lastSubmitTimeRef.current < 500) {
      return;
    }

    const sanitized = sanitizeUrl(inputUrl);
    if (!sanitized) {
      return;
    }

    lastSubmitTimeRef.current = now;
    isSubmittingRef.current = true;

    try {
      onInspect(sanitized);
    } finally {
      setTimeout(() => {
        isSubmittingRef.current = false;
      }, 500);
    }
  };

  const handleSelectPreset = (url: string) => {
    const now = Date.now();
    if (isLoading || isSubmittingRef.current || now - lastSubmitTimeRef.current < 500) {
      return;
    }

    const sanitized = sanitizeUrl(url);
    setInputUrl(sanitized);
    lastSubmitTimeRef.current = now;
    isSubmittingRef.current = true;

    try {
      onInspect(sanitized);
    } finally {
      setTimeout(() => {
        isSubmittingRef.current = false;
      }, 500);
    }
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex items-center rounded-xl bg-zinc-900/90 border border-zinc-800 shadow-2xl focus-within:border-zinc-700 focus-within:ring-1 focus-within:ring-zinc-700 transition-all">
          <div className="pl-4 pr-2 text-zinc-500">
            <Search className="w-5 h-5" />
          </div>

          <input
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            disabled={isLoading}
            placeholder="Enter URL to inspect (e.g. https://auth-verify.account-update.xyz/login)"
            className="w-full py-4 pr-44 sm:pr-48 bg-transparent text-sm sm:text-base font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
            spellCheck={false}
            autoComplete="off"
          />

          <div className="absolute right-2 flex items-center gap-2">
            {inputUrl && (
              <button
                type="button"
                onClick={() => setInputUrl('')}
                className="hidden sm:inline-flex px-2 py-1 text-xs font-mono text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                Clear
              </button>
            )}

            <button
              type="submit"
              disabled={isLoading || !inputUrl.trim()}
              className="flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-lg text-xs sm:text-sm font-medium bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-800 disabled:text-zinc-600 text-zinc-950 transition-all font-mono shadow-md disabled:shadow-none"
            >
              {isLoading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin text-zinc-950" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-4 h-4" />
                  <span>Analyze URL</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Real-time Format Awareness Helper Text */}
      {isPlainWordsWithoutDomain && (
        <div className="mt-2.5 px-1 flex items-center gap-1.5 text-xs font-mono text-zinc-500 animate-in fade-in duration-200">
          <Info className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
          <span>Hint: Enter a resolvable domain or full URL (e.g., domain.com or https://...)</span>
        </div>
      )}

      {/* Preset Targets Quick Selection */}
      <div className="mt-3 flex flex-wrap items-center gap-2 pt-1">
        <span className="text-xs font-mono text-zinc-500 mr-1 flex items-center gap-1">
          <span>Preset Vectors:</span>
        </span>
        {PRESET_TARGETS.map((target) => (
          <button
            key={target.label}
            type="button"
            onClick={() => handleSelectPreset(target.url)}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono bg-zinc-900/80 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800/80 hover:border-zinc-700 transition-all disabled:opacity-50"
          >
            <span>{target.label}</span>
            <ArrowUpRight className="w-3 h-3 text-zinc-500" />
          </button>
        ))}
      </div>
    </div>
  );
}

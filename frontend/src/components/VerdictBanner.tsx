'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Server,
  Clock,
  Lock,
  Unlock,
  CheckCircle2,
  ExternalLink,
} from 'lucide-react';
import { URLAnalysisResponse } from '@/types/analysis';

interface VerdictBannerProps {
  analysis: URLAnalysisResponse;
}

export function VerdictBanner({ analysis }: VerdictBannerProps) {
  const [isMounted, setIsMounted] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const { verdict, is_threat, threat_probability, threshold_applied, latency_ms, url } =
    analysis;

  if (!isMounted) {
    return (
      <div className="w-full rounded-2xl border border-zinc-800/80 bg-zinc-900/50 p-6 sm:p-8 backdrop-blur-xl animate-pulse">
        <div className="flex items-center gap-4 pb-6 border-b border-zinc-800/70">
          <div className="w-14 h-14 sm:w-16 sm:h-16 rounded-xl bg-zinc-800/60 shrink-0" />
          <div className="space-y-2 flex-1">
            <div className="h-6 w-48 bg-zinc-800/60 rounded" />
            <div className="h-4 w-96 max-w-full bg-zinc-800/40 rounded" />
          </div>
        </div>
      </div>
    );
  }

  const scorePct = Math.min(Math.max(threat_probability * 100, 0), 100);
  const thresholdPct = threshold_applied * 100;

  const handleCopy = () => {
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Status-specific themes adhering strictly to guidelines
  const theme = {
    BENIGN: {
      border: 'border-emerald-800/50',
      bg: 'bg-emerald-950/40',
      glow: 'shadow-[0_0_30px_rgba(16,185,129,0.08)]',
      text: 'text-emerald-400',
      badgeBg: 'bg-emerald-900/50',
      badgeBorder: 'border-emerald-700/60',
      icon: ShieldCheck,
      headline: 'BENIGN / VERIFIED SAFE',
      description:
        'No adversarial lexical patterns or phishing signatures detected. Metrics remain safely within established baseline bounds.',
      barColor: 'bg-emerald-500',
    },
    SUSPICIOUS: {
      border: 'border-amber-800/50',
      bg: 'bg-amber-950/40',
      glow: 'shadow-[0_0_30px_rgba(245,158,11,0.08)]',
      text: 'text-amber-400',
      badgeBg: 'bg-amber-900/50',
      badgeBorder: 'border-amber-700/60',
      icon: ShieldAlert,
      headline: 'SUSPICIOUS / ELEVATED RISK',
      description:
        'URL exhibits anomalous indicators exceeding the enforced 5% False Positive Rate threshold. Caution advised.',
      barColor: 'bg-amber-500',
    },
    MALICIOUS: {
      border: 'border-rose-800/50',
      bg: 'bg-rose-950/40',
      glow: 'shadow-[0_0_30px_rgba(244,63,94,0.08)]',
      text: 'text-rose-400',
      badgeBg: 'bg-rose-900/50',
      badgeBorder: 'border-rose-700/60',
      icon: ShieldX,
      headline: 'MALICIOUS / HIGH SEVERITY THREAT',
      description:
        'Critical phishing heuristics identified (e.g. social engineering lures, high entropy, or raw IP host addressing).',
      barColor: 'bg-rose-500',
    },
    INTERNAL_TARGET: {
      border: 'border-indigo-800/60',
      bg: 'bg-indigo-950/40',
      glow: 'shadow-[0_0_35px_rgba(99,102,241,0.12)]',
      text: 'text-indigo-400',
      badgeBg: 'bg-indigo-900/60',
      badgeBorder: 'border-indigo-700/70',
      icon: Server,
      headline: 'INTERNAL TARGET / PRIVATE HOST',
      description:
        'This target points to loopback or private network infrastructure (RFC 1918) and cannot be assessed as a public web threat.',
      barColor: 'bg-indigo-500',
    },
  }[verdict] || {
    border: 'border-zinc-800/50',
    bg: 'bg-zinc-950/40',
    glow: '',
    text: 'text-zinc-400',
    badgeBg: 'bg-zinc-900/50',
    badgeBorder: 'border-zinc-700/60',
    icon: ShieldCheck,
    headline: 'INSPECTED ENDPOINT',
    description: 'URL inspection completed.',
    barColor: 'bg-zinc-500',
  };

  const VerdictIcon = theme.icon;

  return (
    <div
      className={`w-full rounded-2xl border ${theme.border} ${theme.bg} ${theme.glow} p-6 sm:p-8 backdrop-blur-xl transition-all`}
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-zinc-800/70">
        {/* Left: Verdict Identification & Icon */}
        <div className="flex items-start sm:items-center gap-4">
          <div
            className={`w-14 h-14 sm:w-16 sm:h-16 rounded-xl border ${theme.badgeBorder} ${theme.badgeBg} flex items-center justify-center ${theme.text} shrink-0`}
          >
            <VerdictIcon className="w-8 h-8 sm:w-9 sm:h-9" />
          </div>

          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <span
                className={`text-xl sm:text-2xl font-bold font-mono tracking-tight ${theme.text}`}
              >
                {theme.headline}
              </span>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold uppercase tracking-wider border ${theme.badgeBorder} ${theme.badgeBg} ${theme.text}`}
              >
                {verdict === 'INTERNAL_TARGET' ? 'INTERNAL / PRIVATE HOST' : verdict}
              </span>
              {analysis.forensics?.is_allowlisted && (
                <span className="px-2.5 py-0.5 rounded text-xs font-mono font-semibold uppercase tracking-wider border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                  ALLOWLIST VERIFIED
                </span>
              )}
              {analysis.forensics?.dangerous_protocol && (
                <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wider border border-rose-500/70 bg-rose-500/20 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.35)] animate-pulse">
                  CRITICAL: SCRIPT/URI INJECTION
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-zinc-300 max-w-2xl leading-relaxed">
              {analysis.risk_summary ||
                (verdict === 'INTERNAL_TARGET'
                  ? 'This target points to loopback or private network infrastructure (RFC 1918) and cannot be assessed as a public web threat.'
                  : analysis.forensics?.is_allowlisted
                  ? 'Pre-approved high-reputation domain verified by Enterprise Trust Tier. Short-circuited safely per SOC gateway standards.'
                  : theme.description)}
            </p>
          </div>
        </div>

        {/* Right: Numerical Threat Probability */}
        <div className="flex flex-col sm:flex-row lg:flex-col items-start lg:items-end justify-between gap-1 shrink-0 font-mono">
          <div className="text-xs uppercase text-zinc-500 tracking-wider">
            {verdict === 'INTERNAL_TARGET' ? 'Informational Baseline' : 'Threat Probability Score'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-4xl sm:text-5xl font-black ${theme.text}`}>
              {verdict === 'INTERNAL_TARGET' ? '10.0%' : `${(threat_probability * 100).toFixed(1)}%`}
            </span>
            <span className="text-xs text-zinc-500">
              {verdict === 'INTERNAL_TARGET'
                ? '(Non-Routable Baseline)'
                : `/ threshold ${(threshold_applied * 100).toFixed(1)}%`}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-1 text-xs text-zinc-400">
            <Clock className="w-3.5 h-3.5 text-zinc-500" />
            <span>Deterministic latency: {latency_ms.toFixed(2)}ms</span>
          </div>
        </div>
      </div>

      {/* Target Inspected URL Display */}
      <div className="mt-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 rounded-lg bg-zinc-950/70 border border-zinc-850">
        <div className="flex items-center gap-2.5 min-w-0 max-w-full">
          {url.toLowerCase().startsWith('https://') ? (
            <Lock className="w-4 h-4 text-emerald-500 shrink-0" />
          ) : (
            <Unlock className="w-4 h-4 text-amber-500 shrink-0" />
          )}
          <span className="font-mono text-xs sm:text-sm text-zinc-200 truncate select-all">
            {url}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto justify-end">
          <button
            onClick={handleCopy}
            type="button"
            className="px-2.5 py-1 rounded text-xs font-mono text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors"
          >
            {copied ? 'Copied' : 'Copy URL'}
          </button>
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="p-1 rounded text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors"
            title="Inspect in external tab (Caution)"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>

      {/* Visual Risk Gauge & Decision Threshold Bar */}
      <div className="mt-6 pt-2">
        <div className="flex items-center justify-between text-xs font-mono text-zinc-400 mb-2">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>0.0% Benign Floor</span>
          </span>
          <span className="text-zinc-400 font-medium">
            Decision Threshold: {thresholdPct.toFixed(1)}% (Enforced FPR &le; 5.0%)
          </span>
          <span className="flex items-center gap-1.5">
            <span>100.0% Malicious Ceiling</span>
            <ShieldX className="w-3.5 h-3.5 text-rose-400" />
          </span>
        </div>

        {/* Progress Track */}
        <div className="relative w-full h-3 rounded-full bg-zinc-900 border border-zinc-800 overflow-visible">
          {/* Active Probability Bar */}
          <div
            className={`h-full rounded-full ${theme.barColor} transition-all duration-700 ease-out`}
            style={{ width: `${verdict === 'INTERNAL_TARGET' ? 10 : scorePct}%` }}
          />

          {/* Enforced Threshold Marker Line */}
          <div
            className="absolute top-[-4px] bottom-[-4px] w-0.5 bg-zinc-200 z-10"
            style={{ left: `${thresholdPct}%` }}
            title={`Calibrated Policy Threshold: ${thresholdPct.toFixed(2)}%`}
          >
            <div className="absolute -top-5 -translate-x-1/2 px-1.5 py-0.2 rounded bg-zinc-800 border border-zinc-700 text-[9px] font-mono text-zinc-300">
              POLICY
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

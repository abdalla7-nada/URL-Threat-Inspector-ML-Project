'use client';

import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Fingerprint,
  FileCode,
  Activity,
  Layers,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { URLForensics } from '@/types/analysis';

interface RiskSignalsProps {
  forensics: URLForensics;
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'INTERNAL_TARGET';
}

export function RiskSignals({ forensics, verdict }: RiskSignalsProps) {
  const {
    has_ip_host,
    has_punycode,
    suspicious_keywords_count,
    host_entropy,
    digit_ratio,
    path_depth,
    param_count,
    url_length,
  } = forensics;

  const signals = [
    {
      id: 'ip_address',
      name: 'Host Addressing Mode',
      triggered: has_ip_host,
      severity: 'CRITICAL',
      icon: Fingerprint,
      activeMessage:
        'Host contains a raw numeric IPv4/IPv6 address instead of a registered domain. Frequently utilized in short-lived phishing nodes to bypass domain-based reputation filters.',
      benignMessage:
        'Standard domain-based addressing utilized. Compliant with standard DNS infrastructure.',
    },
    {
      id: 'punycode',
      name: 'Homograph / Punycode Analysis',
      triggered: has_punycode,
      severity: 'HIGH',
      icon: AlertTriangle,
      activeMessage:
        "Punycode prefix ('xn--') detected in domain structure. Common vector in Internationalized Domain Name (IDN) homograph visual spoofing attacks.",
      benignMessage:
        'ASCII character encoding verified. No homoglyph or punycode substitution detected.',
    },
    {
      id: 'lures',
      name: 'Social Engineering Lures',
      triggered: suspicious_keywords_count > 0,
      severity: suspicious_keywords_count >= 2 ? 'HIGH' : 'ELEVATED',
      icon: FileCode,
      activeMessage: `${suspicious_keywords_count} security/account credential lure word(s) identified in URL token stream (e.g. login, verify, secure, banking).`,
      benignMessage:
        'Zero credential harvesting or account verification keywords identified in URL stream.',
    },
    {
      id: 'entropy',
      name: 'Host Character Shannon Entropy',
      triggered: host_entropy > 3.8,
      severity: 'ELEVATED',
      icon: Activity,
      activeMessage: `Host entropy of ${host_entropy.toFixed(2)} bits indicates high algorithmic randomness, consistent with Domain Generation Algorithms (DGA) or disposable hostnames.`,
      benignMessage: `Host entropy (${host_entropy.toFixed(2)} bits) aligns with natural human-readable domain linguistics.`,
    },
    {
      id: 'digits',
      name: 'Numeric Digit Saturation',
      triggered: digit_ratio > 0.15,
      severity: 'ELEVATED',
      icon: Layers,
      activeMessage: `Numeric digit ratio of ${(digit_ratio * 100).toFixed(1)}% is elevated. Attackers often append numeric hashes to evade static string matches.`,
      benignMessage: `Digit ratio of ${(digit_ratio * 100).toFixed(1)}% is within normal baseline limits.`,
    },
    {
      id: 'complexity',
      name: 'Path & Parameter Structure',
      triggered: path_depth >= 4 || param_count >= 4 || url_length > 120,
      severity: 'MODERATE',
      icon: FileCode,
      activeMessage: `Excessive hierarchy depth (${path_depth} levels, ${param_count} params, ${url_length} chars). Long nested structures are frequently used to conceal redirection destinations.`,
      benignMessage:
        'Path hierarchy and parameter count conform to normal web navigation structures.',
    },
  ];

  const triggeredCount = signals.filter((s) => s.triggered).length;

  return (
    <div className="w-full rounded-2xl bg-zinc-900/80 border border-zinc-800/80 p-6 backdrop-blur-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-zinc-800/80">
        <div className="flex items-center gap-2.5">
          {triggeredCount > 0 ? (
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          )}
          <h3 className="text-base font-semibold text-zinc-100 font-mono tracking-wide">
            THREAT SIGNAL HEURISTICS MATRIX
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-zinc-400">
            Active Warning Flags:
          </span>
          <span
            className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
              triggeredCount > 0
                ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
            }`}
          >
            {triggeredCount} / {signals.length}
          </span>
        </div>
      </div>

      {/* Signal Rows */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {signals.map((signal) => {
          const SignalIcon = signal.icon;
          return (
            <div
              key={signal.id}
              className={`p-4 rounded-xl border transition-all ${
                signal.triggered
                  ? 'bg-zinc-950/70 border-rose-900/40'
                  : 'bg-zinc-950/40 border-zinc-850/60'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <SignalIcon
                    className={`w-4 h-4 ${
                      signal.triggered ? 'text-rose-400' : 'text-zinc-500'
                    }`}
                  />
                  <span className="text-xs font-mono font-semibold text-zinc-200">
                    {signal.name}
                  </span>
                </div>

                {signal.triggered ? (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950 text-rose-400 border border-rose-800/60 uppercase">
                    {signal.severity}
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 uppercase">
                    NOMINAL
                  </span>
                )}
              </div>

              <p className="text-xs text-zinc-400 leading-relaxed font-sans">
                {signal.triggered ? signal.activeMessage : signal.benignMessage}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

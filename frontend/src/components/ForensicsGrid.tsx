'use client';

import React from 'react';
import {
  Globe,
  Fingerprint,
  FileCode,
  Layers,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import { URLForensics } from '@/types/analysis';

interface ForensicsGridProps {
  forensics: URLForensics;
}

export function ForensicsGrid({ forensics }: ForensicsGridProps) {
  const {
    url_length,
    domain_length,
    path_depth,
    param_count,
    digit_ratio,
    has_ip_host,
    has_punycode,
    host_entropy,
    suspicious_keywords_count,
    tld,
  } = forensics;

  const cards = [
    {
      title: 'Total URL Length',
      value: `${url_length} chars`,
      desc: url_length > 100 ? 'Excessive length' : 'Standard length',
      isWarning: url_length > 100,
      icon: Terminal,
    },
    {
      title: 'Host Domain Length',
      value: `${domain_length} chars`,
      desc: domain_length > 30 ? 'Long host' : 'Standard host',
      isWarning: domain_length > 30,
      icon: Globe,
    },
    {
      title: 'Path Hierarchy Depth',
      value: `${path_depth} levels`,
      desc: path_depth >= 4 ? 'Deep hierarchy' : 'Shallow hierarchy',
      isWarning: path_depth >= 4,
      icon: Layers,
    },
    {
      title: 'Query Parameters',
      value: `${param_count} params`,
      desc: param_count > 3 ? 'High parameter count' : 'Normal parameters',
      isWarning: param_count > 3,
      icon: FileCode,
    },
    {
      title: 'Numeric Digit Ratio',
      value: `${(digit_ratio * 100).toFixed(1)}%`,
      desc: digit_ratio > 0.15 ? 'Elevated digit ratio' : 'Normal digit ratio',
      isWarning: digit_ratio > 0.15,
      icon: Activity,
    },
    {
      title: 'Host Addressing Type',
      value: has_ip_host ? 'RAW IP ADDRESS' : 'DNS Hostname',
      desc: has_ip_host ? 'Severe phishing indicator' : 'Standard FQDN resolution',
      isWarning: has_ip_host,
      icon: Fingerprint,
    },
    {
      title: 'Homograph / Punycode',
      value: has_punycode ? 'PUNYCODE (xn--)' : 'Standard ASCII',
      desc: has_punycode ? 'Potential spoofing attack' : 'Standard character set',
      isWarning: has_punycode,
      icon: AlertTriangle,
    },
    {
      title: 'Host Shannon Entropy',
      value: `${host_entropy.toFixed(2)} bits`,
      desc: host_entropy > 3.8 ? 'High algorithmic randomness' : 'Natural distribution',
      isWarning: host_entropy > 3.8,
      icon: Activity,
    },
    {
      title: 'Identified Lure Keywords',
      value: `${suspicious_keywords_count} detected`,
      desc:
        suspicious_keywords_count > 0
          ? 'Social engineering vocabulary'
          : 'Zero lure tokens found',
      isWarning: suspicious_keywords_count > 0,
      icon: AlertTriangle,
    },
    {
      title: 'Top-Level Domain (TLD)',
      value: `.${tld}`,
      desc: tld === 'other' ? 'Uncommon/non-standard suffix' : 'Recognized top suffix',
      isWarning: tld === 'other',
      icon: Globe,
    },
  ];

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h3 className="text-base font-semibold text-zinc-100 font-mono tracking-wide">
            STRUCTURAL & LEXICAL FORENSICS BREAKDOWN
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {forensics.is_allowlisted && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <CheckCircle2 className="w-3 h-3" />
              ALLOWLISTED
            </span>
          )}
          <span className="text-xs font-mono text-zinc-500">
            10 Extracted Forensic Indicators
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {cards.map((card) => {
          const CardIcon = card.icon;
          return (
            <div
              key={card.title}
              className={`p-4 rounded-xl bg-zinc-900/80 border transition-all ${
                card.isWarning
                  ? 'border-amber-800/40 hover:border-amber-700/60'
                  : 'border-zinc-800/80 hover:border-zinc-700/80'
              }`}
            >
              <div className="flex items-center justify-between text-zinc-500 mb-2">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  {card.title}
                </span>
                <CardIcon
                  className={`w-4 h-4 ${
                    card.isWarning ? 'text-amber-400' : 'text-zinc-500'
                  }`}
                />
              </div>

              <div className="flex items-baseline gap-2">
                <span
                  className={`text-lg font-bold font-mono ${
                    card.isWarning ? 'text-amber-300' : 'text-zinc-100'
                  }`}
                >
                  {card.value}
                </span>
              </div>

              <div className="mt-1 flex items-center gap-1.5 text-[11px] font-mono text-zinc-500">
                {card.isWarning ? (
                  <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0" />
                ) : (
                  <CheckCircle2 className="w-3 h-3 text-emerald-500 shrink-0" />
                )}
                <span className="truncate">{card.desc}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

'use client';

import React, { useState, useEffect } from 'react';
import {
  Clock,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Server,
  FileCode,
} from 'lucide-react';
import { URLAnalysisResponse } from '@/types/analysis';

export interface AuditRecord {
  id: string;
  timestamp: string;
  data: URLAnalysisResponse;
}

interface AuditLogProps {
  records: AuditRecord[];
  onSelect: (record: AuditRecord) => void;
  onClear: () => void;
}

export function AuditLog({ records, onSelect, onClear }: AuditLogProps) {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const handleExportJson = () => {
    if (records.length === 0) return;
    const blob = new Blob([JSON.stringify(records, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersec_url_audit_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!isMounted || records.length === 0) {
    return null;
  }

  return (
    <div className="w-full rounded-2xl bg-zinc-900/80 border border-zinc-800/80 p-6 backdrop-blur-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-emerald-400" />
          <h3 className="text-base font-semibold text-zinc-100 font-mono tracking-wide">
            SESSION INSPECTION AUDIT TRAIL
          </h3>
          <span className="ml-2 px-2 py-0.5 rounded text-xs font-mono bg-zinc-800 text-zinc-300">
            {records.length} {records.length === 1 ? 'Record' : 'Records'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            type="button"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-zinc-800 hover:bg-zinc-750 text-zinc-300 border border-zinc-700/60 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Export Audit Log</span>
          </button>
          <button
            onClick={onClear}
            type="button"
            className="px-3 py-1.5 rounded-lg text-xs font-mono text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors"
          >
            Clear History
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-zinc-800 text-[11px] font-mono uppercase text-zinc-500">
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Inspected URL</th>
              <th className="py-2.5 px-3">Verdict</th>
              <th className="py-2.5 px-3 text-right">Threat Probability</th>
              <th className="py-2.5 px-3 text-right">Latency</th>
              <th className="py-2.5 px-3 text-center">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-850 font-mono text-xs">
            {records.map((r) => {
              const { verdict, threat_probability, latency_ms, url } = r.data;
              const verdictStyle = {
                BENIGN: {
                  badge: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50',
                  icon: ShieldCheck,
                },
                SUSPICIOUS: {
                  badge: 'bg-amber-950/60 text-amber-400 border-amber-800/50',
                  icon: ShieldAlert,
                },
                MALICIOUS: {
                  badge: 'bg-rose-950/60 text-rose-400 border-rose-800/50',
                  icon: ShieldX,
                },
                INTERNAL_TARGET: {
                  badge: 'bg-cyan-950/60 text-cyan-400 border-cyan-800/50',
                  icon: Server,
                },
              }[verdict] || {
                badge: 'bg-zinc-900 text-zinc-400 border-zinc-800',
                icon: ShieldCheck,
              };

              const VIcon = verdictStyle.icon;

              return (
                <tr
                  key={r.id}
                  className="hover:bg-zinc-850/40 transition-colors group"
                >
                  <td className="py-3 px-3 text-zinc-400 whitespace-nowrap">
                    {r.timestamp}
                  </td>
                  <td className="py-3 px-3 text-zinc-200 max-w-xs sm:max-w-md truncate">
                    <span title={url}>{url}</span>
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${verdictStyle.badge}`}
                    >
                      <VIcon className="w-3 h-3 shrink-0" />
                      <span>{verdict}</span>
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right text-zinc-200 font-bold whitespace-nowrap">
                    {(threat_probability * 100).toFixed(1)}%
                  </td>
                  <td className="py-3 px-3 text-right text-zinc-400 whitespace-nowrap">
                    {latency_ms.toFixed(1)}ms
                  </td>
                  <td className="py-3 px-3 text-center whitespace-nowrap">
                    <button
                      onClick={() => onSelect(r)}
                      type="button"
                      className="px-2.5 py-1 rounded text-[11px] font-mono bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

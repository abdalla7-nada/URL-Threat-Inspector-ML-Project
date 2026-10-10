'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Terminal,
  Activity,
  Layers,
  Server,
  AlertTriangle,
  Globe,
  Lock,
} from 'lucide-react';
import { Header } from '@/components/Header';
import { InspectionForm } from '@/components/InspectionForm';
import { VerdictBanner } from '@/components/VerdictBanner';
import { ForensicsGrid } from '@/components/ForensicsGrid';
import { RiskSignals } from '@/components/RiskSignals';
import { AuditLog, AuditRecord } from '@/components/AuditLog';
import { EngineSpecsModal } from '@/components/EngineSpecsModal';
import { SyntaxNoticeBanner } from '@/components/SyntaxNoticeBanner';
import { inspectUrl, ApiError } from '@/lib/api';
import { URLAnalysisResponse } from '@/types/analysis';

const INITIAL_DEMO_URL =
  'https://secure-login-verify-account.example.com/update';

export default function Home() {
  const [analysis, setAnalysis] = useState<URLAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [syntaxNotice, setSyntaxNotice] = useState<{
    title: string;
    message: string;
    recommendation?: string;
  } | null>(null);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [isSpecsOpen, setIsSpecsOpen] = useState(false);
  const [isMounted, setIsMounted] = useState(false);

  // Load persisted audit records from localStorage if present
  useEffect(() => {
    setIsMounted(true);
    try {
      const stored = localStorage.getItem('cybersec_audit_records');
      if (stored) {
        setAuditRecords(JSON.parse(stored));
      }
    } catch {
      // LocalStorage access fallback
    }
  }, []);

  // Save audit records
  const saveAuditRecords = (newRecords: AuditRecord[]) => {
    setAuditRecords(newRecords);
    try {
      localStorage.setItem(
        'cybersec_audit_records',
        JSON.stringify(newRecords)
      );
    } catch {
      // LocalStorage access fallback
    }
  };

  const handleInspect = async (url: string) => {
    setIsLoading(true);
    setErrorMessage(null);
    setSyntaxNotice(null);

    try {
      const result = await inspectUrl(url);
      setAnalysis(result);
      setSyntaxNotice(null);

      // Append to audit trail
      const newRecord: AuditRecord = {
        id: `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        timestamp: new Date().toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        data: result,
      };

      const updated = [newRecord, ...auditRecords.slice(0, 19)];
      saveAuditRecords(updated);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.errorType === 'INVALID_URL_SYNTAX') {
        setSyntaxNotice({
          title: 'INVALID INPUT SYNTAX',
          message: err.message,
          recommendation:
            'Please ensure your input contains a valid top-level domain or network protocol.',
        });
        setAnalysis(null);
      } else {
        const msg =
          err instanceof Error ? err.message : 'Inspection execution failed.';
        if (
          msg.includes('INVALID_URL_SYNTAX') ||
          msg.toLowerCase().includes('plain text') ||
          msg.toLowerCase().includes('incomplete query')
        ) {
          setSyntaxNotice({
            title: 'INVALID INPUT SYNTAX',
            message: msg.replace(/\[?INVALID_URL_SYNTAX\]?:?\s*/i, ''),
            recommendation:
              'Please ensure your input contains a valid top-level domain or network protocol.',
          });
          setAnalysis(null);
        } else {
          setErrorMessage(msg);
        }
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectAudit = (record: AuditRecord) => {
    setAnalysis(record.data);
    setErrorMessage(null);
    setSyntaxNotice(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleClearAudit = () => {
    saveAuditRecords([]);
  };

  if (!isMounted) {
    return (
      <div
        suppressHydrationWarning
        className="min-h-screen flex flex-col bg-zinc-950 text-zinc-100 bg-radar-grid"
      >
        <div className="w-full h-16 border-b border-zinc-800/80 bg-zinc-950/80" />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12" />
      </div>
    );
  }

  return (
    <div
      suppressHydrationWarning
      className="min-h-screen flex flex-col bg-zinc-950 text-zinc-100 bg-radar-grid"
    >
      {/* Top SOC Navigation Bar */}
      <Header
        onOpenSpecs={() => setIsSpecsOpen(true)}
        latency={analysis ? analysis.latency_ms : null}
      />

      {/* Main Command Console Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 space-y-8">
        {/* Executive Hero Banner */}
        <div className="text-center sm:text-left max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300 mb-4">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>ENTERPRISE NETWORK PERIMETER THREAT ASSESSMENT</span>
          </div>

          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black tracking-tight text-zinc-100 font-mono">
            URL SECURITY & THREAT INSPECTOR
          </h1>

          <p className="mt-3 text-sm sm:text-base text-zinc-400 font-sans leading-relaxed">
            Deterministic lexical and structural threat classification powered by a
            gradient boosted decision tree ensemble. Enforces calibrated false positive
            rate policy (&le; 5%) for zero protocol-recording bias.
          </p>

          <div className="mt-3 inline-flex items-center gap-2 text-xs font-mono text-zinc-500">
            <span className="px-2.5 py-1 rounded border border-zinc-800/80 bg-zinc-900/60">
              SCOPE: Deterministic Lexical &amp; Structural ML (Zero-Payload Static Analysis)
            </span>
          </div>
        </div>

        {/* Command Console Inspection Form */}
        <section aria-label="URL Inspection Console">
          <InspectionForm onInspect={handleInspect} isLoading={isLoading} />
        </section>

        {/* Input Syntax Notice Banner (HTTP 400 Gateway Rejection) */}
        {syntaxNotice && (
          <div className="animate-in fade-in duration-300">
            <SyntaxNoticeBanner
              title={syntaxNotice.title}
              message={syntaxNotice.message}
              recommendation={syntaxNotice.recommendation}
              onDismiss={() => setSyntaxNotice(null)}
            />
          </div>
        )}

        {/* Error Notification Banner */}
        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-sm font-mono flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <span className="font-bold">INSPECTION ENGINE ERROR:</span>{' '}
              {errorMessage}
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-xs text-rose-400 hover:text-rose-200 uppercase font-bold"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Live Verdict & Forensics Display Section */}
        {analysis ? (
          <div className="space-y-8 animate-in fade-in duration-300">
            {/* Primary Dynamic Verdict Banner */}
            <VerdictBanner analysis={analysis} />

            {/* 10-Point Forensic Indicator Grid */}
            <ForensicsGrid forensics={analysis.forensics} />

            {/* Threat Signal Heuristics Matrix */}
            <RiskSignals
              forensics={analysis.forensics}
              verdict={analysis.verdict}
            />
          </div>
        ) : (
          /* Initial Empty / Idle State */
          <div className="rounded-2xl border border-zinc-800/70 bg-zinc-900/40 p-8 sm:p-12 text-center backdrop-blur-sm">
            <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-400 mx-auto mb-4">
              <ShieldCheck className="w-8 h-8 text-emerald-400/80" />
            </div>

            <h2 className="text-lg sm:text-xl font-bold font-mono text-zinc-200">
              INSPECTION CONSOLE STANDBY
            </h2>

            <p className="mt-2 text-sm text-zinc-400 max-w-xl mx-auto">
              Submit a target URL in the command console above or select a preset vector
              to run full deterministic forensic extraction and threat classification.
            </p>

            <div className="mt-6 flex flex-wrap items-center justify-center gap-4 text-xs font-mono text-zinc-500">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-zinc-400" />
                <span>29 Forensic Metrics</span>
              </span>
              <span>&bull;</span>
              <span className="flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                <span>FPR &le; 0.05 Policy Enforced</span>
              </span>
              <span>&bull;</span>
              <span className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-zinc-400" />
                <span>LightGBM Gradient Boost Engine</span>
              </span>
            </div>
          </div>
        )}

        {/* Session Audit Trail History */}
        <section aria-label="Inspection Audit Trail">
          <AuditLog
            records={auditRecords}
            onSelect={handleSelectAudit}
            onClear={handleClearAudit}
          />
        </section>
      </main>

      {/* Engine Technical Specifications Modal */}
      <EngineSpecsModal
        isOpen={isSpecsOpen}
        onClose={() => setIsSpecsOpen(false)}
      />

      {/* Footer & SOC Compliance */}
      <footer className="w-full border-t border-zinc-900 bg-zinc-950/90 py-6 text-xs font-mono text-zinc-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>CYBERSEC URL THREAT INSPECTOR &bull; DETERMINISTIC PIPELINE</span>
          </div>
          <div>
            <span>Model Trained on 522k Verified URLs &bull; Zero Protocol Bias</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

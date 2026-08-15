import React from 'react';
import { Layers, CopyX, ShieldBan, CheckCircle2, ArrowRight, Percent, Zap } from 'lucide-react';

export default function NoiseReductionFunnel({ metrics, scannerBreakdown }) {
  if (!metrics) return null;

  const rawCount = metrics.raw_count || 0;
  const duplicateCount = metrics.duplicate_count || 0;
  const suppressedCount = metrics.suppressed_count || 0;
  const finalCount = metrics.final_count || 0;

  const dedupPct = metrics.dedup_pct || (rawCount ? ((duplicateCount / rawCount) * 100).toFixed(1) : 0);
  const fpPct = metrics.fp_removed_pct || (rawCount ? ((suppressedCount / rawCount) * 100).toFixed(1) : 0);
  const noiseReductionPct = metrics.noise_reduction_pct || (rawCount ? (((duplicateCount + suppressedCount) / rawCount) * 100).toFixed(1) : 0);

  return (
    <div className="space-y-3">
      {/* Executive Telemetry Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Card 1: Raw Ingestion */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-800/80 relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-blue-500 to-indigo-500"></div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 font-mono tracking-wider uppercase">
              1. Raw Findings
            </span>
            <div className="w-8 h-8 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-black text-slate-100 font-mono tracking-tight">
              {rawCount}
            </span>
            <span className="text-xs text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded-full border border-blue-800/50 font-mono">
              3 Scanners
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Unfiltered alerts ingested from Nuclei, Nmap & OWASP ZAP
          </p>
        </div>

        {/* Card 2: Duplicates Stripped */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-800/80 relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-amber-500 to-orange-500"></div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 font-mono tracking-wider uppercase">
              2. Duplicates Removed
            </span>
            <div className="w-8 h-8 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <CopyX className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-black text-amber-400 font-mono tracking-tight">
              -{duplicateCount}
            </span>
            <span className="text-xs text-amber-300 bg-amber-950/60 px-2 py-0.5 rounded-full border border-amber-800/50 font-mono">
              -{dedupPct}% Noise
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Cross-scanner correlation via exact CVE, host & endpoint matching
          </p>
        </div>

        {/* Card 3: Suppressed FP */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 border border-slate-800/80 relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-purple-500 to-pink-500"></div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 font-mono tracking-wider uppercase">
              3. Suppressed & FP
            </span>
            <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <ShieldBan className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-black text-purple-400 font-mono tracking-tight">
              -{suppressedCount}
            </span>
            <span className="text-xs text-purple-300 bg-purple-950/60 px-2 py-0.5 rounded-full border border-purple-800/50 font-mono">
              -{fpPct}% Filtered
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            Below-threshold info banners & accepted business risks
          </p>
        </div>

        {/* Card 4: Actionable Ranked Output */}
        <div className="glass-card glass-card-hover rounded-2xl p-4 border border-cyan-500/30 relative overflow-hidden group glow-cyan">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-cyan-400 to-emerald-400"></div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-cyan-300 font-mono tracking-wider uppercase">
              4. Ranked Action List
            </span>
            <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline justify-between">
            <span className="text-3xl font-black text-cyan-300 font-mono tracking-tight">
              {finalCount}
            </span>
            <span className="text-xs font-bold text-emerald-400 bg-emerald-950/80 px-2.5 py-0.5 rounded-full border border-emerald-700/60 font-mono flex items-center space-x-1">
              <Zap className="w-3 h-3 fill-current" />
              <span>-{noiseReductionPct}% Total Noise</span>
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-300">
            Enriched with KEV/EPSS & scored for developer remediation
          </p>
        </div>
      </div>
    </div>
  );
}

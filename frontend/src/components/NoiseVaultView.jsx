import React, { useState } from 'react';
import { CopyX, ShieldBan, Info, CheckCircle2, ArrowRight } from 'lucide-react';

export default function NoiseVaultView({ duplicateFindings, suppressedFindings }) {
  const [subTab, setSubTab] = useState('duplicates'); // 'duplicates' | 'suppressed'

  return (
    <div className="space-y-4">
      {/* Header & Sub-Tab Switcher */}
      <div className="glass-card rounded-2xl p-4 border border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <ShieldBan className="w-5 h-5 text-indigo-400" />
            <span>Noise Reduction & Audit Traceability Vault</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Transparent record of all raw scanner noise stripped before reaching engineering tickets.
          </p>
        </div>

        <div className="flex items-center space-x-2 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setSubTab('duplicates')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all ${
              subTab === 'duplicates'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <CopyX className="w-3.5 h-3.5" />
            <span>Duplicates Removed ({duplicateFindings.length})</span>
          </button>

          <button
            onClick={() => setSubTab('suppressed')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all ${
              subTab === 'suppressed'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldBan className="w-3.5 h-3.5" />
            <span>Suppressed / False Positives ({suppressedFindings.length})</span>
          </button>
        </div>
      </div>

      {/* Sub-Tab 1: Duplicates */}
      {subTab === 'duplicates' && (
        <div className="glass-card rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="p-4 bg-amber-950/20 border-b border-amber-900/30 text-xs text-amber-200 flex items-center space-x-2">
            <Info className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              These findings were detected by multiple overlapping scanners and merged into canonical master items.
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {duplicateFindings.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No duplicate findings in this scan.
              </div>
            ) : (
              duplicateFindings.map((f, idx) => (
                <div key={f.finding_id || idx} className="p-4 hover:bg-slate-900/40 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/60">
                          {f.source_scanner}
                        </span>
                        <h3 className="text-sm font-bold text-slate-200">{f.title}</h3>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 font-mono">
                        Target: {f.host}:{f.port || 'all'} | Deduplication Rule: <strong className="text-amber-300">{f.dedup_method || 'exact_cve_host'}</strong>
                      </p>
                    </div>

                    <div className="text-right text-xs font-mono">
                      <span className="text-slate-500">Merged into Canonical ID:</span>
                      <div className="text-cyan-400 text-[11px] truncate max-w-xs">{f.duplicate_of || 'canonical-root'}</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Sub-Tab 2: Suppressed & FP */}
      {subTab === 'suppressed' && (
        <div className="glass-card rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="p-4 bg-purple-950/20 border-b border-purple-900/30 text-xs text-purple-200 flex items-center space-x-2">
            <Info className="w-4 h-4 text-purple-400 shrink-0" />
            <span>
              These findings were filtered out of active tickets based on suppression policies (e.g. info-only or accepted risk).
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {suppressedFindings.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No suppressed findings in this scan.
              </div>
            ) : (
              suppressedFindings.map((f, idx) => (
                <div key={f.finding_id || idx} className="p-4 hover:bg-slate-900/40 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60">
                          {f.source_scanner}
                        </span>
                        <h3 className="text-sm font-bold text-slate-200">{f.title}</h3>
                      </div>
                      <p className="text-xs text-slate-400 mt-1 font-mono">
                        Target: {f.host}:{f.port || 'all'}
                      </p>
                    </div>

                    <div className="p-2.5 rounded-xl bg-slate-900/90 border border-purple-900/40 text-xs max-w-md">
                      <span className="text-[10px] font-mono uppercase text-purple-400 font-bold block mb-0.5">
                        Suppression Justification:
                      </span>
                      <p className="text-slate-300 text-[11px] font-sans">
                        {f.suppression_reason || "Filtered by organizational policy threshold."}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

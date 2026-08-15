import React from 'react';
import { Shield, RefreshCw, Terminal, Play, ExternalLink, Activity, Sparkles, Layers } from 'lucide-react';

export default function Navbar({
  scans,
  currentScanId,
  onSelectScan,
  onTriggerScan,
  isTriggering,
  activeTab,
  setActiveTab,
  metrics
}) {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#080c16]/90 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Subtitle */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2.5">
              <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
                <Shield className="w-5 h-5 text-white" />
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
                </span>
              </div>
              <span className="text-xl font-black tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-400 font-mono">
                THREAT-X
              </span>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center space-x-1 pl-6 border-l border-slate-800">
              <button
                onClick={() => setActiveTab('actionable')}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeTab === 'actionable'
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Ranked Action List</span>
                {metrics?.final_count !== undefined && (
                  <span className="ml-1 px-1.5 py-0.2 text-[10px] rounded-full bg-cyan-900/60 text-cyan-300 font-mono">
                    {metrics.final_count}
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('noise_reduction')}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeTab === 'noise_reduction'
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Layers className="w-3.5 h-3.5 text-indigo-400" />
                <span>Noise Telemetry & Vault</span>
                {metrics?.duplicate_count !== undefined && (
                  <span className="ml-1 px-1.5 py-0.2 text-[10px] rounded-full bg-indigo-950 text-indigo-300 font-mono">
                    {metrics.duplicate_count + (metrics.suppressed_count || 0)}
                  </span>
                )}
              </button>
            </nav>
          </div>

          {/* Right Action Bar */}
          <div className="flex items-center space-x-3">
            {/* Scan Selector */}
            <div className="flex items-center space-x-2">
              <label htmlFor="scan-select" className="text-xs text-slate-400 hidden lg:block font-mono">
                Active Scan:
              </label>
              <select
                id="scan-select"
                value={currentScanId}
                onChange={(e) => onSelectScan(e.target.value)}
                className="bg-slate-900/90 text-slate-200 text-xs rounded-xl border border-slate-700/80 px-3 py-1.5 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer shadow-sm"
              >
                {scans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    Scan ID: {s.scan_id}
                  </option>
                ))}
              </select>
            </div>

            {/* Run Pipeline Button */}
            <button
              onClick={onTriggerScan}
              disabled={isTriggering}
              className="flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white text-xs font-semibold shadow-md shadow-cyan-500/20 transition-all transform hover:-translate-y-0.5 active:translate-y-0 cursor-pointer"
            >
              {isTriggering ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Pipeline</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}

import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  Flame, 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  Cpu, 
  Clock, 
  User, 
  ExternalLink, 
  ChevronRight,
  Sparkles,
  BarChart3,
  SlidersHorizontal,
  Info
} from 'lucide-react';

const SCANNER_STYLES = {
  nuclei: 'bg-blue-950/80 text-blue-300 border-blue-800/80',
  nmap: 'bg-orange-950/80 text-orange-300 border-orange-800/80',
  zap: 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80'
};

const SLA_TIER_STYLES = {
  critical: 'bg-rose-950/90 text-rose-300 border-rose-700/80 shadow-rose-950/50',
  high: 'bg-amber-950/90 text-amber-300 border-amber-700/80 shadow-amber-950/50',
  medium: 'bg-yellow-950/90 text-yellow-300 border-yellow-700/80 shadow-yellow-950/50',
  low: 'bg-emerald-950/90 text-emerald-300 border-emerald-700/80 shadow-emerald-950/50'
};

export default function ActionableFindingsTable({ findings, onSelectFinding }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScanner, setSelectedScanner] = useState('all');
  const [selectedTier, setSelectedTier] = useState('all');
  const [selectedHost, setSelectedHost] = useState('all');
  const [kevOnly, setKevOnly] = useState(false);
  const [minScore, setMinScore] = useState(0);

  // Available unique hosts
  const uniqueHosts = useMemo(() => {
    const hosts = new Set(findings.map((f) => f.host).filter(Boolean));
    return Array.from(hosts).sort();
  }, [findings]);

  // Filtered and sorted findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const title = (f.title || '').toLowerCase();
          const host = (f.host || '').toLowerCase();
          const cves = Array.isArray(f.cve_ids) ? f.cve_ids.join(' ').toLowerCase() : String(f.cve_ids || '').toLowerCase();
          const desc = (f.description || '').toLowerCase();
          if (!title.includes(q) && !host.includes(q) && !cves.includes(q) && !desc.includes(q)) {
            return false;
          }
        }

        // Scanner filter
        if (selectedScanner !== 'all') {
          const scanners = f.contributing_label ? f.contributing_label.toLowerCase() : (f.source_scanner || '').toLowerCase();
          if (!scanners.includes(selectedScanner.toLowerCase())) return false;
        }

        // Tier filter
        if (selectedTier !== 'all') {
          if ((f.sla_tier || '').toLowerCase() !== selectedTier.toLowerCase()) return false;
        }

        // Host filter
        if (selectedHost !== 'all') {
          if (f.host !== selectedHost) return false;
        }

        // KEV Only
        if (kevOnly && !f.in_kev) return false;

        // Min score
        const score = typeof f.risk_score === 'number' ? f.risk_score : 0;
        if (score < minScore) return false;

        return true;
      })
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  }, [findings, searchQuery, selectedScanner, selectedTier, selectedHost, kevOnly, minScore]);

  return (
    <div className="space-y-4">
      {/* Search & Filter Bar */}
      <div className="glass-card rounded-2xl p-4 border border-slate-800/90 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings by CVE (e.g. CVE-2021-44228), title, host, or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-900/90 text-slate-200 text-xs rounded-xl border border-slate-700/70 focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-slate-500 font-mono shadow-inner"
            />
          </div>

          {/* Quick Filter Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Scanner Selector */}
            <select
              value={selectedScanner}
              onChange={(e) => setSelectedScanner(e.target.value)}
              className="bg-slate-900 text-slate-300 text-xs rounded-xl border border-slate-700/80 px-3 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono cursor-pointer"
            >
              <option value="all">All Scanners</option>
              <option value="nuclei">Nuclei</option>
              <option value="nmap">Nmap</option>
              <option value="zap">OWASP ZAP</option>
            </select>

            {/* SLA Tier */}
            <select
              value={selectedTier}
              onChange={(e) => setSelectedTier(e.target.value)}
              className="bg-slate-900 text-slate-300 text-xs rounded-xl border border-slate-700/80 px-3 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono cursor-pointer"
            >
              <option value="all">All SLA Tiers</option>
              <option value="critical">P0 Critical</option>
              <option value="high">P1 High</option>
              <option value="medium">P2 Medium</option>
              <option value="low">P3 Low</option>
            </select>

            {/* Host Filter */}
            <select
              value={selectedHost}
              onChange={(e) => setSelectedHost(e.target.value)}
              className="bg-slate-900 text-slate-300 text-xs rounded-xl border border-slate-700/80 px-3 py-2 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono cursor-pointer"
            >
              <option value="all">All Hosts</option>
              {uniqueHosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>

            {/* KEV Toggle Button */}
            <button
              onClick={() => setKevOnly(!kevOnly)}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-xl text-xs font-bold border transition-all cursor-pointer ${
                kevOnly
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/60 shadow-md shadow-rose-950/40'
                  : 'bg-slate-900 text-slate-400 border-slate-700/80 hover:text-slate-200'
              }`}
            >
              <Flame className={`w-3.5 h-3.5 ${kevOnly ? 'text-rose-400 fill-rose-400' : 'text-slate-500'}`} />
              <span>CISA KEV Only</span>
            </button>
          </div>
        </div>

        {/* Score Range Slider Bar */}
        <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400 font-mono">
          <div className="flex items-center space-x-3">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Minimum Risk Score:</span>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-32 accent-cyan-400 cursor-pointer"
            />
            <span className="text-cyan-300 font-bold px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
              {minScore}+
            </span>
          </div>

          <div className="text-[11px] text-slate-400">
            Showing <strong className="text-slate-200">{filteredFindings.length}</strong> of{' '}
            <strong className="text-slate-200">{findings.length}</strong> actionable findings
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-card rounded-2xl border border-slate-800/90 overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/90 text-slate-400 font-mono text-[11px] uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4 font-semibold">Rank & Risk Score</th>
                <th className="py-3.5 px-4 font-semibold">SLA Tier</th>
                <th className="py-3.5 px-4 font-semibold">Finding / CVE</th>
                <th className="py-3.5 px-4 font-semibold">Target Asset</th>
                <th className="py-3.5 px-4 font-semibold">Threat Intel & Exploitation</th>
                <th className="py-3.5 px-4 font-semibold">Found By</th>
                <th className="py-3.5 px-4 font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-12 text-slate-400">
                    <Info className="w-8 h-8 text-slate-500 mx-auto mb-2 opacity-60" />
                    <p className="font-semibold">No actionable findings match the selected filters.</p>
                    <p className="text-[11px] text-slate-500 mt-1">Try clearing your search query or relaxing filter thresholds.</p>
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding, idx) => {
                  const score = typeof finding.risk_score === 'number' ? finding.risk_score.toFixed(1) : '—';
                  const tier = (finding.sla_tier || 'low').toLowerCase();
                  const cves = Array.isArray(finding.cve_ids) ? finding.cve_ids : [];
                  const epssPct = typeof finding.epss_score === 'number' ? (finding.epss_score * 100).toFixed(1) : null;
                  const cvss = typeof finding.cvss_v3_score === 'number' ? finding.cvss_v3_score.toFixed(1) : null;

                  return (
                    <tr
                      key={finding.finding_id || idx}
                      onClick={() => onSelectFinding(finding)}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    >
                      {/* Score & Rank */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex items-center space-x-2.5">
                          <span className="text-[11px] font-mono text-slate-500 font-bold w-5">
                            #{idx + 1}
                          </span>
                          <div className="flex items-center space-x-2">
                            <span className={`text-base font-black font-mono px-2.5 py-1 rounded-xl border ${
                              finding.risk_score >= 80
                                ? 'bg-rose-950/80 text-rose-300 border-rose-700/80 shadow-sm shadow-rose-950'
                                : finding.risk_score >= 50
                                ? 'bg-amber-950/80 text-amber-300 border-amber-700/80'
                                : 'bg-slate-900 text-cyan-300 border-slate-700'
                            }`}>
                              {score}
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* SLA Tier */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-[11px] font-bold font-mono uppercase tracking-wide border ${
                          SLA_TIER_STYLES[tier] || SLA_TIER_STYLES.low
                        }`}>
                          <span>{tier}</span>
                        </span>
                      </td>

                      {/* Title & CVE */}
                      <td className="py-3.5 px-4 max-w-sm">
                        <div>
                          <p className="font-semibold text-slate-100 text-xs leading-snug group-hover:text-cyan-300 transition-colors">
                            {finding.title}
                          </p>
                          <div className="flex flex-wrap items-center gap-1.5 mt-1">
                            {cves.length > 0 ? (
                              cves.map((cve) => (
                                <span
                                  key={cve}
                                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60"
                                >
                                  {cve}
                                </span>
                              ))
                            ) : (
                              <span className="text-[10px] text-slate-500 font-mono">No CVE Assigned</span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Host & Port */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="font-mono text-xs">
                          <span className="text-slate-200 font-semibold">{finding.host}</span>
                          {finding.port && (
                            <span className="text-cyan-400 ml-1">:{finding.port}</span>
                          )}
                          {finding.service && (
                            <div className="text-[10px] text-slate-400">{finding.service}</div>
                          )}
                        </div>
                      </td>

                      {/* Threat Intel Badges */}
                      <td className="py-3.5 px-4">
                        <div className="flex flex-wrap items-center gap-1.5">
                          {/* CISA KEV */}
                          {finding.in_kev ? (
                            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px] font-mono font-bold animate-pulse-slow">
                              <Flame className="w-3 h-3 text-rose-400 fill-rose-400" />
                              <span>CISA KEV</span>
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-500 font-mono">No KEV</span>
                          )}

                          {/* EPSS */}
                          {epssPct !== null && (
                            <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold border ${
                              Number(epssPct) > 50
                                ? 'bg-amber-950/80 text-amber-300 border-amber-800/80'
                                : 'bg-slate-900 text-slate-300 border-slate-700/60'
                            }`}>
                              EPSS: {epssPct}%
                            </span>
                          )}

                          {/* CVSS */}
                          {cvss !== null && (
                            <span className="px-1.5 py-0.5 rounded-md bg-slate-900 text-slate-400 border border-slate-800 text-[10px] font-mono">
                              CVSS {cvss}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Found By (Scanners) */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div className="flex flex-wrap items-center gap-1">
                          {(finding.contributing_label || finding.source_scanner || 'unknown')
                            .split(' + ')
                            .map((sc) => {
                              const key = sc.trim().toLowerCase();
                              return (
                                <span
                                  key={key}
                                  className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold uppercase border ${
                                    SCANNER_STYLES[key] || 'bg-slate-900 text-slate-300 border-slate-700'
                                  }`}
                                >
                                  {key}
                                </span>
                              );
                            })}
                        </div>
                      </td>

                      {/* Action Button */}
                      <td className="py-3.5 px-4 whitespace-nowrap text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectFinding(finding);
                          }}
                          className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700/60 hover:border-cyan-500/40 text-[11px] font-semibold transition-all cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

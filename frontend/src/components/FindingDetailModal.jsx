import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Flame, 
  Sparkles, 
  Clock, 
  User, 
  ExternalLink, 
  BarChart3, 
  FileCode, 
  Tag, 
  Layers, 
  Check, 
  Copy,
  GitPullRequest
} from 'lucide-react';

export default function FindingDetailModal({ finding, isOpen, onClose }) {
  const [copied, setCopied] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState('overview'); // 'overview' | 'evidence' | 'ticket'

  if (!isOpen || !finding) return null;

  const scoreBreakdown = finding.score_breakdown || {};
  const breakdownItems = Object.entries(scoreBreakdown).filter(
    ([k]) => k !== 'raw_total_before_clip' && k !== 'final_score'
  );

  const rawEvidenceStr = typeof finding.raw_evidence === 'object'
    ? JSON.stringify(finding.raw_evidence, null, 2)
    : String(finding.raw_evidence || '{}');

  const cves = Array.isArray(finding.cve_ids) ? finding.cve_ids : [];

  const copyEvidence = () => {
    navigator.clipboard.writeText(rawEvidenceStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md overflow-y-auto animate-fade-in">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0f172a] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden text-slate-200">
        
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-slate-800 bg-slate-900/90">
          <div className="space-y-1.5 pr-6">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded-lg text-xs font-mono font-bold uppercase border ${
                finding.sla_tier === 'critical'
                  ? 'bg-rose-950/90 text-rose-300 border-rose-700'
                  : finding.sla_tier === 'high'
                  ? 'bg-amber-950/90 text-amber-300 border-amber-700'
                  : 'bg-cyan-950/90 text-cyan-300 border-cyan-700'
              }`}>
                {finding.sla_tier || 'P3 Low'} SLA
              </span>

              <span className="px-2.5 py-0.5 rounded-lg bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700">
                Score: <strong className="text-cyan-300">{Number(finding.risk_score || 0).toFixed(1)} / 100</strong>
              </span>

              {finding.in_kev && (
                <span className="px-2 py-0.5 rounded-lg bg-rose-500/20 text-rose-300 text-xs font-mono font-bold border border-rose-500/40 flex items-center space-x-1">
                  <Flame className="w-3.5 h-3.5 text-rose-400 fill-rose-400" />
                  <span>CISA KEV Active Exploit</span>
                </span>
              )}
            </div>

            <h2 className="text-lg font-bold text-slate-100 leading-tight">
              {finding.title}
            </h2>

            <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono">
              <span>Target: <strong className="text-slate-200">{finding.host}:{finding.port || 'all'}</strong></span>
              <span>•</span>
              <span>Found by: <strong className="text-cyan-300">{finding.contributing_label || finding.source_scanner}</strong></span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Sub Navigation Bar */}
        <div className="flex items-center space-x-2 px-5 py-2.5 bg-slate-900/60 border-b border-slate-800/80 text-xs font-semibold">
          <button
            onClick={() => setActiveSubTab('overview')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeSubTab === 'overview'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Overview & Score Breakdown
          </button>
          <button
            onClick={() => setActiveSubTab('evidence')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeSubTab === 'evidence'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Evidence JSON
          </button>
          <button
            onClick={() => setActiveSubTab('ticket')}
            className={`px-3 py-1 rounded-lg transition-all ${
              activeSubTab === 'ticket'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Remediation & Ticket
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1">
          {activeSubTab === 'overview' && (
            <div className="space-y-5">
              {/* AI Explainability Box */}
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/40 relative">
                <div className="flex items-center space-x-2 text-cyan-300 text-xs font-bold uppercase tracking-wider mb-1.5">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span>Explainable Threat Context & AI Analysis</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {finding.ai_summary || finding.description || "Finding enriched across public intelligence sources (NVD, EPSS, and CISA KEV). Prioritized due to high exploitability and asset exposure."}
                </p>
              </div>

              {/* Score Breakdown (Explainable Scoring Model) */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                    <span>Explainable Risk Formula Points</span>
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    Total: <strong className="text-cyan-300">{finding.risk_score}</strong> / 100
                  </span>
                </div>

                <div className="space-y-2.5">
                  {breakdownItems.length > 0 ? (
                    breakdownItems.map(([factor, pts]) => {
                      const numPts = Number(pts) || 0;
                      const maxFactorVal = 40; // visual scaling
                      const widthPct = Math.min(100, Math.max(5, (numPts / maxFactorVal) * 100));

                      return (
                        <div key={factor} className="space-y-1">
                          <div className="flex items-center justify-between text-xs font-mono">
                            <span className="text-slate-400 capitalize">{factor.replace(/_/g, ' ')}</span>
                            <span className="text-cyan-300 font-bold">+{numPts.toFixed(1)} pts</span>
                          </div>
                          <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500"
                              style={{ width: `${widthPct}%` }}
                            ></div>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <p className="text-xs text-slate-500">No score breakdown available for this item.</p>
                  )}
                </div>
              </div>

              {/* Threat Intel & Asset Matrix */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
                {/* Left: Intelligence Attributes */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
                  <h4 className="font-bold text-slate-300 font-mono uppercase text-[11px]">Threat Intelligence</h4>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">CVSS v3.1 Base:</span>
                    <span className="text-slate-200 font-bold">{finding.cvss_v3_score || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">EPSS Exploit Probability:</span>
                    <span className="text-slate-200 font-bold">
                      {finding.epss_score ? `${(finding.epss_score * 100).toFixed(2)}%` : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">CISA KEV Weaponized:</span>
                    <span className={finding.in_kev ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                      {finding.in_kev ? 'YES (Confirmed In Wild)' : 'NO'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 font-mono">
                    <span className="text-slate-400">Exploit-DB Available:</span>
                    <span className={finding.exploit_db_available ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                      {finding.exploit_db_available ? 'YES' : 'NO'}
                    </span>
                  </div>
                </div>

                {/* Right: Asset & SLA Details */}
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
                  <h4 className="font-bold text-slate-300 font-mono uppercase text-[11px]">Remediation SLA & Ownership</h4>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">Asset Criticality:</span>
                    <span className="text-cyan-300 font-bold uppercase">{finding.asset_criticality || 'Tier-1'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">Assigned Team:</span>
                    <span className="text-slate-200">{finding.team || 'AppSec Ops'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80 font-mono">
                    <span className="text-slate-400">Finding Owner:</span>
                    <span className="text-slate-200">{finding.owner || 'devsecops-lead'}</span>
                  </div>
                  <div className="flex justify-between py-1 font-mono">
                    <span className="text-slate-400">SLA Due Date:</span>
                    <span className="text-amber-400 font-bold">{finding.sla_due_date || 'Within 24 Hours'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'evidence' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Heterogeneous scanner JSON evidence payload</span>
                <button
                  onClick={copyEvidence}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>

              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto max-h-96 leading-relaxed">
                {rawEvidenceStr}
              </pre>
            </div>
          )}

          {activeSubTab === 'ticket' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <GitPullRequest className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-slate-200 font-mono uppercase">
                      Ticket-Ready GitHub / Jira Action Payload
                    </span>
                  </div>
                  {finding.github_issue_url && (
                    <a
                      href={finding.github_issue_url}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center space-x-1 text-xs text-cyan-400 hover:underline font-mono"
                    >
                      <span>View Linked Issue</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 space-y-2">
                  <p><strong className="text-cyan-300">Issue Title:</strong> [SEC-{finding.sla_tier?.toUpperCase() || 'P0'}] {finding.title} on {finding.host}</p>
                  <p><strong className="text-cyan-300">Assignee:</strong> @{finding.owner || 'security-team'}</p>
                  <p><strong className="text-cyan-300">SLA Due Date:</strong> {finding.sla_due_date || 'Immediate'}</p>
                  <p><strong className="text-cyan-300">Prioritization Risk Score:</strong> {finding.risk_score} / 100</p>
                  <div className="pt-2 border-t border-slate-800 text-slate-400">
                    <p className="font-semibold text-slate-300 mb-1">Recommended Remediation Steps:</p>
                    <ul className="list-disc pl-4 space-y-1">
                      <li>Patch affected component or upgrade dependency version to latest secure release.</li>
                      <li>Verify firewall / security group access to host {finding.host}:{finding.port || 'all'}.</li>
                      <li>Re-run Threat-X scanner audit pipeline to automatically verify mitigation.</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <span className="text-xs text-slate-500 font-mono">
            Finding ID: {finding.finding_id || 'uuid-fixture'}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

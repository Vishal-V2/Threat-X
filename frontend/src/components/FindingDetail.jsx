import React from 'react';
import { Sparkles, ShieldAlert, Cpu, CheckCircle } from 'lucide-react';
import ScoreBreakdown from './ScoreBreakdown';
import EvidenceViewer from './EvidenceViewer';
import TicketAssignment from './TicketAssignment';

export default function FindingDetail({
  finding,
  allFilteredFindings,
  onSelectFinding,
  scanId,
  onTicketUpdated,
}) {
  if (!finding) {
    return (
      <div className="detail-panel">
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px' }}>
          Select a finding from the table to view detailed analysis.
        </div>
      </div>
    );
  }

  const tierClass = finding.sla_tier ? `sla-${finding.sla_tier.toLowerCase()}` : '';

  return (
    <div className="detail-panel">
      {/* Finding Selector Dropdown (matching Streamlit selector) */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
        <div className="section-title">
          <ShieldAlert size={20} color="var(--accent-cyan)" />
          <span>Finding Detail</span>
        </div>

        <select
          className="input-text"
          style={{ maxWidth: '420px', cursor: 'pointer' }}
          value={finding.finding_id}
          onChange={(e) => {
            const match = allFilteredFindings.find((f) => f.finding_id === e.target.value);
            if (match) onSelectFinding(match);
          }}
        >
          {allFilteredFindings.map((f) => (
            <option key={f.finding_id} value={f.finding_id}>
              [{f.risk_score?.toFixed(1) ?? '—'}] {f.title.substring(0, 50)} — {f.host}
            </option>
          ))}
        </select>
      </div>

      {/* Header Info */}
      <div className="detail-header">
        <div className="detail-title-row">
          <div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: '800', fontFamily: 'var(--font-heading)', color: 'var(--text-primary)' }}>
              {finding.title}
            </h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '6px', flexWrap: 'wrap' }}>
              <span className={`sla-badge ${tierClass}`}>
                {finding.sla_tier || 'UNASSIGNED'}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                Target: {finding.host}{finding.port ? `:${finding.port}` : ''}
              </span>
              {finding.service && (
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Service: {finding.service}
                </span>
              )}
              {finding.in_kev && (
                <span className="kev-badge">CISA KEV ACTIVE</span>
              )}
            </div>
          </div>

          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: '600' }}>
              Risk Score
            </span>
            <span
              className="score-cell"
              style={{
                fontSize: '2rem',
                lineHeight: '1',
                color: (finding.risk_score || 0) >= 80 ? '#f87171' : (finding.risk_score || 0) >= 50 ? '#fb923c' : '#4ade80',
              }}
            >
              {finding.risk_score != null ? finding.risk_score.toFixed(1) : '—'}
            </span>
          </div>
        </div>

        {/* Metadata Grid */}
        <div className="detail-meta-grid">
          <div className="meta-item">
            <span className="meta-label">SLA Due Date</span>
            <span className="meta-val" style={{ fontFamily: 'var(--font-mono)' }}>
              {finding.sla_due_date || '—'}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Owner / Team</span>
            <span className="meta-val">
              {finding.owner || '—'} {finding.team ? `(${finding.team})` : ''}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Contributing Scanners</span>
            <span className="meta-val" style={{ color: 'var(--accent-blue)' }}>
              {finding.contributing_label || finding.source_scanner}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-label">CVSS / EPSS / Exploit-DB</span>
            <span className="meta-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
              CVSS {finding.cvss_v3_score?.toFixed(1) ?? '—'} | EPSS {finding.epss_score != null ? `${(finding.epss_score * 100).toFixed(1)}%` : '—'} | {finding.exploit_db_available ? 'Exploit Available' : 'No Public Exploit'}
            </span>
          </div>
        </div>
      </div>

      {/* AI Summary Banner */}
      <div className="ai-summary-card">
        <div className="ai-summary-title">
          <Sparkles size={16} />
          <span>Why this matters</span>
        </div>
        <p className="ai-summary-text">
          {finding.ai_summary || (
            <span style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>
              (AI summary not generated — set GEMINI_API_KEY)
            </span>
          )}
        </p>
      </div>

      {/* Score Breakdown & Actions Grid */}
      <div className="detail-content-grid">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.88rem', fontWeight: '700' }}>
            <Cpu size={16} color="var(--accent-blue)" />
            <span>Score Breakdown (points contributed)</span>
          </div>
          <ScoreBreakdown breakdown={finding.score_breakdown} />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <TicketAssignment
            scanId={scanId}
            finding={finding}
            onTicketUpdated={onTicketUpdated}
          />
          <EvidenceViewer evidence={finding.raw_evidence} />
        </div>
      </div>
    </div>
  );
}

import React, { useEffect } from 'react';
import { X, FileText, Activity, Server, UserCheck, Shield } from 'lucide-react';
import { SlaBadge, KevBadge, ScoreBadge } from '../common/Badge';
import ScoreBreakdown from './ScoreBreakdown';
import FindingEvidence from './FindingEvidence';
import FindingTicket from './FindingTicket';

export default function FindingDrawer({
  finding,
  onClose,
  scanId,
  onTicketUpdated,
}) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!finding) return null;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="drawer-content" onClick={(e) => e.stopPropagation()}>
        {/* Drawer Header */}
        <div className="drawer-header">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <SlaBadge tier={finding.sla_tier} />
              <KevBadge active={finding.in_kev} />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {finding.source_scanner}
              </span>
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.3 }}>
              {finding.title}
            </h3>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
                Risk Score
              </div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
                {finding.risk_score != null ? finding.risk_score.toFixed(1) : '—'}
              </div>
            </div>
            <button
              onClick={onClose}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
              title="Close drawer (Esc)"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Drawer Body */}
        <div className="drawer-body">
          {/* Asset & Location */}
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-item-label">Target Host</span>
              <span className="detail-item-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {finding.host}{finding.port ? `:${finding.port}` : ''}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">Service / Protocol</span>
              <span className="detail-item-value">
                {finding.service || '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">CVE IDs</span>
              <span className="detail-item-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {finding.cve_ids && finding.cve_ids.length > 0 ? finding.cve_ids.join(', ') : 'None'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">Contributing Scanners</span>
              <span className="detail-item-value">
                {finding.contributing_label || finding.source_scanner}
              </span>
            </div>
          </div>

          {/* Risk Metrics & SLA */}
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-item-label">CVSS Base Score</span>
              <span className="detail-item-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {finding.cvss_v3_score != null ? finding.cvss_v3_score.toFixed(1) : '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">EPSS Exploit Likelihood</span>
              <span className="detail-item-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {finding.epss_score != null ? `${(finding.epss_score * 100).toFixed(1)}%` : '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">Remediation Due</span>
              <span className="detail-item-value" style={{ fontFamily: 'var(--font-mono)' }}>
                {finding.sla_due_date || '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-item-label">Assigned Owner</span>
              <span className="detail-item-value">
                {finding.owner || '—'} {finding.team ? `(${finding.team})` : ''}
              </span>
            </div>
          </div>

          {/* Score Breakdown */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Risk Score Breakdown
            </span>
            <ScoreBreakdown breakdown={finding.score_breakdown} />
          </div>

          {/* Analyst Summary */}
          <div className="analyst-summary-box">
            <div className="analyst-summary-title">
              <FileText size={14} />
              <span>Analyst Summary</span>
            </div>
            <div className="analyst-summary-content">
              {finding.ai_summary || (
                <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  No automated summary generated for this finding.
                </span>
              )}
            </div>
          </div>

          {/* Issue Tracking */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Issue Tracking & Assignment
            </span>
            <FindingTicket
              scanId={scanId}
              finding={finding}
              onTicketUpdated={onTicketUpdated}
            />
          </div>

          {/* Raw Evidence */}
          <FindingEvidence evidence={finding.raw_evidence} />
        </div>
      </div>
    </div>
  );
}

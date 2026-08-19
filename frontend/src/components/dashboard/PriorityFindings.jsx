import React from 'react';
import { SlaBadge, KevBadge, ScoreBadge } from '../common/Badge';
import { ArrowRight, AlertTriangle } from 'lucide-react';

export default function PriorityFindings({ findings = [], onSelectFinding, onViewAll }) {
  const topFindings = findings.slice(0, 6);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <AlertTriangle size={15} color="var(--sev-critical)" />
          <span>Priority Actionable Findings</span>
        </div>
        <button
          className="btn btn-secondary"
          style={{ fontSize: '11.5px', padding: '3px 8px' }}
          onClick={onViewAll}
        >
          <span>View all findings</span>
          <ArrowRight size={12} />
        </button>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="enterprise-table">
          <thead>
            <tr>
              <th style={{ width: '60px' }}>Score</th>
              <th style={{ width: '80px' }}>SLA</th>
              <th>Finding</th>
              <th>Host</th>
              <th style={{ width: '50px' }}>KEV</th>
              <th>CVE(s)</th>
            </tr>
          </thead>
          <tbody>
            {topFindings.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  No actionable findings for this scan.
                </td>
              </tr>
            ) : (
              topFindings.map((f) => (
                <tr key={f.finding_id} onClick={() => onSelectFinding(f)}>
                  <td>
                    <ScoreBadge score={f.risk_score} />
                  </td>
                  <td>
                    <SlaBadge tier={f.sla_tier} />
                  </td>
                  <td style={{ fontWeight: 600, maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={f.title}>
                    {f.title}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    {f.host}
                  </td>
                  <td>
                    <KevBadge active={f.in_kev} />
                  </td>
                  <td>
                    {f.cve_ids && f.cve_ids.length > 0 ? (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--primary)' }}>
                        {f.cve_ids.slice(0, 2).join(', ')}
                        {f.cve_ids.length > 2 ? ` +${f.cve_ids.length - 2}` : ''}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-subtle)' }}>—</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

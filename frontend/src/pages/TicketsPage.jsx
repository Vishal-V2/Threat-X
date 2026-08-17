import React from 'react';
import { Ticket, ExternalLink, ShieldCheck } from 'lucide-react';
import { SlaBadge, ScoreBadge } from '../components/common/Badge';
import { EmptyState } from '../components/common/EmptyState';
import FindingDrawer from '../components/findings/FindingDrawer';

export default function TicketsPage({
  scanId,
  findings = [],
  selectedFinding,
  onSelectFinding,
  onCloseFinding,
  onTicketUpdated,
}) {
  const ticketedFindings = findings.filter((f) => f.github_issue_number != null);

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">Remediation Issue Tracking</h2>
          <p className="page-subtitle">
            Synchronized GitHub issues created for high-priority findings in scan <code style={{ fontFamily: 'var(--font-mono)' }}>{scanId}</code>
          </p>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Ticket size={15} color="var(--primary)" />
            <span>GitHub Tracked Issues ({ticketedFindings.length})</span>
          </div>
        </div>

        {ticketedFindings.length === 0 ? (
          <div className="card-body">
            <EmptyState
              title="No GitHub tickets created for this scan yet"
              message="Run the ticketing phase via CLI with GITHUB_TOKEN & GITHUB_REPO configured to automatically create issues for top-scored findings:"
              actionText="Run CLI Ticket Command"
              onAction={() => {}}
            />
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="enterprise-table">
              <thead>
                <tr>
                  <th style={{ width: '80px' }}>Issue #</th>
                  <th style={{ width: '65px' }}>Score</th>
                  <th style={{ width: '80px' }}>SLA</th>
                  <th>Finding Title</th>
                  <th>Host</th>
                  <th>Owner</th>
                  <th>Due Date</th>
                  <th style={{ width: '120px' }}>GitHub Link</th>
                </tr>
              </thead>
              <tbody>
                {ticketedFindings.map((f) => {
                  const isActive = f.finding_id === selectedFinding?.finding_id;
                  return (
                    <tr
                      key={f.finding_id}
                      className={isActive ? 'active-row' : ''}
                      onClick={() => onSelectFinding(f)}
                    >
                      <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--primary)' }}>
                        #{f.github_issue_number}
                      </td>
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
                      <td>{f.owner || '—'}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{f.sla_due_date || '—'}</td>
                      <td>
                        {f.github_issue_url ? (
                          <a
                            href={f.github_issue_url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', color: 'var(--primary)', textDecoration: 'none', fontWeight: 600, fontSize: '11.5px' }}
                          >
                            View Issue <ExternalLink size={11} />
                          </a>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-out Drawer */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          onClose={onCloseFinding}
          scanId={scanId}
          onTicketUpdated={onTicketUpdated}
        />
      )}
    </div>
  );
}

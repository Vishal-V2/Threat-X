import React, { useState } from 'react';
import { ExternalLink, ArrowUpDown, Search, AlertCircle } from 'lucide-react';

export default function FindingsTable({
  findings,
  selectedFindingId,
  onSelectFinding,
  totalActionableCount,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState('risk_score');
  const [sortAsc, setSortAsc] = useState(false);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // Default to desc for metrics
    }
  };

  // Search filter
  const searchedFindings = findings.filter((f) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      (f.title && f.title.toLowerCase().includes(term)) ||
      (f.host && f.host.toLowerCase().includes(term)) ||
      (f.owner && f.owner.toLowerCase().includes(term)) ||
      (f.cve_ids && f.cve_ids.some((c) => c.toLowerCase().includes(term))) ||
      (f.contributing_label && f.contributing_label.toLowerCase().includes(term))
    );
  });

  // Sort
  const sortedFindings = [...searchedFindings].sort((a, b) => {
    let valA = a[sortField];
    let valB = b[sortField];

    if (valA === null || valA === undefined) valA = sortAsc ? Infinity : -Infinity;
    if (valB === null || valB === undefined) valB = sortAsc ? Infinity : -Infinity;

    if (typeof valA === 'string') {
      return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    return sortAsc ? valA - valB : valB - valA;
  });

  return (
    <div className="table-card">
      <div className="table-header-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700', fontFamily: 'var(--font-heading)' }}>
            Ranked Action List
          </h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            ({findings.length} of {totalActionableCount} findings)
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', maxWidth: '280px' }}>
          <div style={{ position: 'relative', width: '100%' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search title, CVE, host..."
              className="input-text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '30px' }}
            />
          </div>
        </div>
      </div>

      <div className="table-scroll-wrap">
        <table className="soc-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('risk_score')}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Score <ArrowUpDown size={12} />
                </div>
              </th>
              <th onClick={() => handleSort('sla_tier')}>SLA</th>
              <th onClick={() => handleSort('title')}>Finding</th>
              <th onClick={() => handleSort('host')}>Host</th>
              <th>CVE(s)</th>
              <th onClick={() => handleSort('in_kev')}>KEV</th>
              <th onClick={() => handleSort('epss_score')}>EPSS</th>
              <th onClick={() => handleSort('cvss_v3_score')}>CVSS</th>
              <th>Found by</th>
              <th onClick={() => handleSort('owner')}>Owner</th>
              <th onClick={() => handleSort('sla_due_date')}>Due</th>
              <th>Ticket</th>
            </tr>
          </thead>
          <tbody>
            {sortedFindings.length === 0 ? (
              <tr>
                <td colSpan="12" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                    <AlertCircle size={24} />
                    <span>No findings match the current filters.</span>
                  </div>
                </td>
              </tr>
            ) : (
              sortedFindings.map((f) => {
                const isSelected = f.finding_id === selectedFindingId;
                const tierClass = f.sla_tier ? `sla-${f.sla_tier.toLowerCase()}` : '';

                return (
                  <tr
                    key={f.finding_id}
                    className={isSelected ? 'selected' : ''}
                    onClick={() => onSelectFinding(f)}
                  >
                    <td className="score-cell" style={{ color: f.risk_score >= 80 ? '#f87171' : f.risk_score >= 50 ? '#fb923c' : '#4ade80' }}>
                      {f.risk_score != null ? f.risk_score.toFixed(1) : '—'}
                    </td>
                    <td>
                      {f.sla_tier ? (
                        <span className={`sla-badge ${tierClass}`}>{f.sla_tier}</span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td style={{ fontWeight: '600', maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={f.title}>
                      {f.title}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {f.host}
                    </td>
                    <td>
                      {f.cve_ids && f.cve_ids.length > 0 ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                          {f.cve_ids.slice(0, 2).map((cve) => (
                            <span key={cve} className="cve-pill">
                              {cve}
                            </span>
                          ))}
                          {f.cve_ids.length > 2 && (
                            <span className="cve-pill" style={{ color: 'var(--text-muted)' }}>
                              +{f.cve_ids.length - 2}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                    <td>
                      {f.in_kev ? (
                        <span className="kev-badge">YES</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>No</span>
                      )}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {f.epss_score != null ? `${(f.epss_score * 100).toFixed(1)}%` : '—'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {f.cvss_v3_score != null ? f.cvss_v3_score.toFixed(1) : '—'}
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {f.contributing_label || f.source_scanner}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.8rem' }}>{f.owner || '—'}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {f.sla_due_date || '—'}
                    </td>
                    <td>
                      {f.github_issue_url ? (
                        <a
                          href={f.github_issue_url}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--accent-cyan)', textDecoration: 'none', fontSize: '0.8rem' }}
                        >
                          #{f.github_issue_number} <ExternalLink size={12} />
                        </a>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

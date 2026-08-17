import React, { useState } from 'react';
import { SlaBadge, KevBadge, ScoreBadge } from '../common/Badge';
import { ArrowUpDown, ExternalLink, SlidersHorizontal, ChevronLeft, ChevronRight } from 'lucide-react';
import { EmptyState } from '../common/EmptyState';

export default function FindingsTable({
  findings = [],
  selectedFindingId,
  onSelectFinding,
}) {
  const [sortField, setSortField] = useState('risk_score');
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [showColumnMenu, setShowColumnMenu] = useState(false);

  // Column visibility state
  const [visibleColumns, setVisibleColumns] = useState({
    score: true,
    sla: true,
    title: true,
    host: true,
    cve: true,
    kev: true,
    epss: true,
    cvss: true,
    scanner: true,
    owner: true,
    due: true,
    ticket: true,
  });

  const toggleColumn = (col) => {
    setVisibleColumns((prev) => ({ ...prev, [col]: !prev[col] }));
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default desc
    }
  };

  // Sort findings
  const sorted = [...findings].sort((a, b) => {
    let valA = a[sortField];
    let valB = b[sortField];

    if (valA === null || valA === undefined) valA = sortAsc ? Infinity : -Infinity;
    if (valB === null || valB === undefined) valB = sortAsc ? Infinity : -Infinity;

    if (typeof valA === 'string') {
      return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    return sortAsc ? valA - valB : valB - valA;
  });

  // Pagination
  const totalPages = Math.ceil(sorted.length / pageSize) || 1;
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="table-container">
      {/* Table Action Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface)', borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Showing <strong>{paginated.length}</strong> findings
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', position: 'relative' }}>
          {/* Column Toggle Button */}
          <button
            className="btn btn-secondary"
            style={{ padding: '3px 8px', fontSize: '11px' }}
            onClick={() => setShowColumnMenu(!showColumnMenu)}
          >
            <SlidersHorizontal size={12} />
            <span>Columns</span>
          </button>

          {/* Column Visibility Menu */}
          {showColumnMenu && (
            <div
              style={{
                position: 'absolute',
                right: 0,
                top: '32px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-medium)',
                borderRadius: 'var(--radius-sm)',
                boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                padding: '8px 12px',
                zIndex: 50,
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '6px',
                width: '240px',
              }}
            >
              {Object.keys(visibleColumns).map((col) => (
                <label key={col} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns[col]}
                    onChange={() => toggleColumn(col)}
                  />
                  <span style={{ textTransform: 'capitalize' }}>{col}</span>
                </label>
              ))}
            </div>
          )}

          {/* Page size select */}
          <select
            className="filter-select"
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
            style={{ padding: '2px 6px', fontSize: '11px' }}
          >
            <option value={10}>10 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
            <option value={100}>100 / page</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="table-responsive">
        <table className="enterprise-table">
          <thead>
            <tr>
              {visibleColumns.score && (
                <th onClick={() => handleSort('risk_score')} style={{ width: '65px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    Score <ArrowUpDown size={11} />
                  </div>
                </th>
              )}
              {visibleColumns.sla && (
                <th onClick={() => handleSort('sla_tier')} style={{ width: '80px' }}>
                  SLA
                </th>
              )}
              {visibleColumns.title && (
                <th onClick={() => handleSort('title')}>
                  Finding Title
                </th>
              )}
              {visibleColumns.host && (
                <th onClick={() => handleSort('host')}>
                  Host
                </th>
              )}
              {visibleColumns.cve && <th>CVE(s)</th>}
              {visibleColumns.kev && (
                <th onClick={() => handleSort('in_kev')} style={{ width: '55px' }}>
                  KEV
                </th>
              )}
              {visibleColumns.epss && (
                <th onClick={() => handleSort('epss_score')} style={{ width: '65px' }}>
                  EPSS
                </th>
              )}
              {visibleColumns.cvss && (
                <th onClick={() => handleSort('cvss_v3_score')} style={{ width: '60px' }}>
                  CVSS
                </th>
              )}
              {visibleColumns.scanner && <th>Found by</th>}
              {visibleColumns.owner && (
                <th onClick={() => handleSort('owner')}>Owner</th>
              )}
              {visibleColumns.due && (
                <th onClick={() => handleSort('sla_due_date')} style={{ width: '90px' }}>
                  Due
                </th>
              )}
              {visibleColumns.ticket && (
                <th style={{ width: '70px' }}>Ticket</th>
              )}
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 ? (
              <tr>
                <td colSpan="12">
                  <EmptyState
                    title="No findings match current filters"
                    message="Try clearing or broadening your search criteria."
                  />
                </td>
              </tr>
            ) : (
              paginated.map((f) => {
                const isActive = f.finding_id === selectedFindingId;
                return (
                  <tr
                    key={f.finding_id}
                    className={isActive ? 'active-row' : ''}
                    onClick={() => onSelectFinding(f)}
                  >
                    {visibleColumns.score && (
                      <td>
                        <ScoreBadge score={f.risk_score} />
                      </td>
                    )}
                    {visibleColumns.sla && (
                      <td>
                        <SlaBadge tier={f.sla_tier} />
                      </td>
                    )}
                    {visibleColumns.title && (
                      <td style={{ fontWeight: 600, maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={f.title}>
                        {f.title}
                      </td>
                    )}
                    {visibleColumns.host && (
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        {f.host}
                      </td>
                    )}
                    {visibleColumns.cve && (
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
                    )}
                    {visibleColumns.kev && (
                      <td>
                        <KevBadge active={f.in_kev} />
                      </td>
                    )}
                    {visibleColumns.epss && (
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        {f.epss_score != null ? `${(f.epss_score * 100).toFixed(1)}%` : '—'}
                      </td>
                    )}
                    {visibleColumns.cvss && (
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        {f.cvss_v3_score != null ? f.cvss_v3_score.toFixed(1) : '—'}
                      </td>
                    )}
                    {visibleColumns.scanner && (
                      <td style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        {f.contributing_label || f.source_scanner}
                      </td>
                    )}
                    {visibleColumns.owner && (
                      <td>
                        <span style={{ fontSize: '11.5px' }}>{f.owner || '—'}</span>
                      </td>
                    )}
                    {visibleColumns.due && (
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                        {f.sla_due_date || '—'}
                      </td>
                    )}
                    {visibleColumns.ticket && (
                      <td>
                        {f.github_issue_url ? (
                          <a
                            href={f.github_issue_url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', color: 'var(--primary)', textDecoration: 'none', fontSize: '11.5px', fontWeight: 600 }}
                          >
                            #{f.github_issue_number} <ExternalLink size={11} />
                          </a>
                        ) : (
                          <span style={{ color: 'var(--text-subtle)' }}>—</span>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 14px', background: 'var(--bg-surface-subtle)', borderTop: '1px solid var(--border-subtle)', fontSize: '11.5px' }}>
          <span>
            Page <strong>{page}</strong> of {totalPages}
          </span>
          <div style={{ display: 'flex', gap: '4px' }}>
            <button
              className="btn btn-secondary"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              style={{ padding: '3px 8px' }}
            >
              <ChevronLeft size={13} />
              Previous
            </button>
            <button
              className="btn btn-secondary"
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
              style={{ padding: '3px 8px' }}
            >
              Next
              <ChevronRight size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

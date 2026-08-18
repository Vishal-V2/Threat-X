import React from 'react';
import { RefreshCw, Layers, User } from 'lucide-react';

export default function Topbar({
  activeView,
  scans = [],
  selectedScanId,
  onSelectScan,
  onRefresh,
  loading,
  lastUpdated,
}) {
  const viewTitles = {
    overview: 'Overview',
    findings: 'Findings',
    scans: 'Scans',
    tickets: 'Tickets',
  };

  return (
    <header className="app-topbar">
      <div className="topbar-left">
        <div className="topbar-breadcrumbs">
          <span>Threat-X</span>
          <span>/</span>
          <span className="active">{viewTitles[activeView] || 'Overview'}</span>
        </div>
      </div>

      <div className="topbar-right">
        {/* Scan Selector */}
        <div className="scan-dropdown-wrapper">
          <Layers size={14} color="var(--text-muted)" />
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Scan:</span>
          <select
            className="scan-select"
            value={selectedScanId || ''}
            onChange={(e) => onSelectScan(e.target.value)}
            disabled={loading || scans.length === 0}
          >
            {scans.map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.scan_id} {s.is_latest ? '(latest)' : ''}
              </option>
            ))}
          </select>
        </div>

        {/* Refresh Button */}
        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={loading}
          title="Refresh current scan data"
        >
          <RefreshCw size={13} className={loading ? 'spinner' : ''} />
          <span>Refresh</span>
        </button>

        {/* User profile tag */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', paddingLeft: '8px', borderLeft: '1px solid var(--border-subtle)', fontSize: '12px', color: 'var(--text-muted)' }}>
          <div style={{ width: '24px', height: '24px', borderRadius: '50%', background: 'var(--bg-surface-subtle)', border: '1px solid var(--border-medium)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-main)' }}>
            <User size={13} />
          </div>
          <span style={{ fontWeight: 500, color: 'var(--text-main)' }}>SOC Analyst</span>
        </div>
      </div>
    </header>
  );
}

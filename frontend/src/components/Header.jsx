import React from 'react';
import { Shield, RefreshCw, Activity, Layers } from 'lucide-react';

export default function Header({ scans, selectedScanId, onSelectScan, onRefresh, loading }) {
  return (
    <header className="header">
      <div className="header-brand">
        <div className="brand-icon-wrapper">
          <Shield size={22} strokeWidth={2.5} />
        </div>
        <div className="brand-titles">
          <h1>Threat-X</h1>
          <span>Risk Prioritization Dashboard</span>
        </div>
      </div>

      <div className="header-actions">
        <div className="scan-select-wrap">
          <Layers size={16} className="text-secondary" />
          <span className="scan-select-label">Scan:</span>
          <select
            id="scan-selector"
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

        <button
          id="refresh-btn"
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={loading}
          title="Refresh scan data"
        >
          <RefreshCw size={15} className={loading ? 'spinner' : ''} />
          <span>Refresh</span>
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#22c55e' }}>
          <Activity size={14} />
          <span>API Connected</span>
        </div>
      </div>
    </header>
  );
}

import React from 'react';
import { Filter, RotateCcw, AlertOctagon } from 'lucide-react';

export default function Filters({
  scannerFilter,
  onScannerChange,
  tierFilter,
  onTierChange,
  hostFilter,
  onHostChange,
  availableHosts = [],
  kevOnly,
  onKevChange,
  minScore,
  onMinScoreChange,
  onResetFilters,
}) {
  const scanners = ['nuclei', 'nmap', 'zap'];
  const tiers = ['critical', 'high', 'medium', 'low'];

  const toggleScanner = (scanner) => {
    if (scannerFilter.includes(scanner)) {
      onScannerChange(scannerFilter.filter((s) => s !== scanner));
    } else {
      onScannerChange([...scannerFilter, scanner]);
    }
  };

  const toggleTier = (tier) => {
    if (tierFilter.includes(tier)) {
      onTierChange(tierFilter.filter((t) => t !== tier));
    } else {
      onTierChange([...tierFilter, tier]);
    }
  };

  const toggleHost = (host) => {
    if (hostFilter.includes(host)) {
      onHostChange(hostFilter.filter((h) => h !== host));
    } else {
      onHostChange([...hostFilter, host]);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="sidebar-header">
        <span className="sidebar-title">
          <Filter size={16} /> Filters
        </span>
        <button
          className="btn btn-secondary"
          onClick={onResetFilters}
          style={{ padding: '4px 8px', fontSize: '0.72rem' }}
          title="Reset all filters"
        >
          <RotateCcw size={12} /> Reset
        </button>
      </div>

      {/* Scanner filter */}
      <div className="filter-group">
        <span className="filter-label">Scanner</span>
        <div className="chip-group">
          {scanners.map((s) => {
            const active = scannerFilter.includes(s);
            return (
              <span
                key={s}
                className={`filter-chip ${active ? 'active' : ''}`}
                onClick={() => toggleScanner(s)}
              >
                {s}
              </span>
            );
          })}
        </div>
      </div>

      {/* SLA Tier filter */}
      <div className="filter-group">
        <span className="filter-label">SLA Tier</span>
        <div className="chip-group">
          {tiers.map((t) => {
            const active = tierFilter.includes(t);
            return (
              <span
                key={t}
                className={`filter-chip ${active ? 'active' : ''}`}
                onClick={() => toggleTier(t)}
              >
                {t}
              </span>
            );
          })}
        </div>
      </div>

      {/* Host filter */}
      <div className="filter-group">
        <span className="filter-label">Host ({availableHosts.length})</span>
        <div className="chip-group" style={{ maxHeight: '120px', overflowY: 'auto' }}>
          {availableHosts.map((h) => {
            const active = hostFilter.includes(h);
            return (
              <span
                key={h}
                className={`filter-chip ${active ? 'active' : ''}`}
                onClick={() => toggleHost(h)}
                title={h}
              >
                {h.length > 22 ? `${h.substring(0, 20)}...` : h}
              </span>
            );
          })}
        </div>
      </div>

      {/* KEV Only checkbox */}
      <div className="filter-group">
        <label className="filter-checkbox-label">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => onKevChange(e.target.checked)}
            style={{ accentColor: 'var(--accent-cyan)' }}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertOctagon size={15} color="#ef4444" />
            <span>KEV only (Active Exploitation)</span>
          </div>
        </label>
      </div>

      {/* Minimum Risk Score slider */}
      <div className="filter-group">
        <div className="filter-range-wrap">
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', fontWeight: '600' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Minimum Risk Score</span>
            <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{minScore}</span>
          </div>
          <input
            type="range"
            min="0"
            max="100"
            step="1"
            value={minScore}
            onChange={(e) => onMinScoreChange(Number(e.target.value))}
            className="filter-range"
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            <span>0</span>
            <span>50</span>
            <span>100</span>
          </div>
        </div>
      </div>
    </div>
  );
}

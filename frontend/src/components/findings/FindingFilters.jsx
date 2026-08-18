import React from 'react';
import { Search, X, RotateCcw } from 'lucide-react';

export default function FindingFilters({
  searchTerm,
  onSearchChange,
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
  scope = 'actionable',
  onScopeChange,
  onResetFilters,
  totalFiltered,
  totalCount,
}) {
  const scanners = ['nuclei', 'nmap', 'zap'];
  const tiers = ['critical', 'high', 'medium', 'low'];

  const hasActiveFilters =
    searchTerm ||
    scannerFilter.length > 0 ||
    tierFilter.length > 0 ||
    hostFilter.length > 0 ||
    kevOnly ||
    minScore > 0 ||
    scope !== 'actionable';

  return (
    <div className="filter-bar">
      <div className="filter-controls-row">
        {/* Search */}
        <div className="filter-search-box">
          <Search size={13} style={{ position: 'absolute', left: '8px', top: '7px', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="filter-search-input"
            placeholder="Filter findings, CVE, host..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
          />
        </div>

        {/* Filter Dropdowns */}
        <div className="filter-inputs-group">
          {/* Scope Selector */}
          {onScopeChange && (
            <select
              className="filter-select"
              value={scope}
              onChange={(e) => onScopeChange(e.target.value)}
              style={{ fontWeight: 600, color: scope !== 'actionable' ? 'var(--primary)' : 'var(--text-main)' }}
            >
              <option value="actionable">Scope: Actionable</option>
              <option value="dedup_fp">Scope: Deduplicated / FP</option>
              <option value="all">Scope: All Ingested</option>
            </select>
          )}

          {/* Scanner */}
          <select
            className="filter-select"
            value={scannerFilter[0] || ''}
            onChange={(e) => onScannerChange(e.target.value ? [e.target.value] : [])}
          >
            <option value="">Scanner: All</option>
            {scanners.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          {/* SLA Tier */}
          <select
            className="filter-select"
            value={tierFilter[0] || ''}
            onChange={(e) => onTierChange(e.target.value ? [e.target.value] : [])}
          >
            <option value="">SLA: All</option>
            {tiers.map((t) => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </select>

          {/* Host */}
          <select
            className="filter-select"
            value={hostFilter[0] || ''}
            onChange={(e) => onHostChange(e.target.value ? [e.target.value] : [])}
            style={{ maxWidth: '180px' }}
          >
            <option value="">Host: All</option>
            {availableHosts.map((h) => (
              <option key={h} value={h}>{h}</option>
            ))}
          </select>

          {/* KEV Checkbox */}
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', color: 'var(--text-main)', cursor: 'pointer', padding: '0 4px' }}>
            <input
              type="checkbox"
              checked={kevOnly}
              onChange={(e) => onKevChange(e.target.checked)}
              style={{ accentColor: 'var(--sev-critical)' }}
            />
            <span style={{ fontWeight: 600 }}>KEV Only</span>
          </label>

          {/* Score Slider */}
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--text-muted)', borderLeft: '1px solid var(--border-subtle)', paddingLeft: '8px' }}>
            <span>Min Score:</span>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={minScore}
              onChange={(e) => onMinScoreChange(Number(e.target.value))}
              style={{ width: '80px', accentColor: 'var(--primary)', cursor: 'pointer' }}
            />
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-main)', minWidth: '22px' }}>
              {minScore}
            </span>
          </div>
        </div>

        {/* Count & Reset */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginLeft: 'auto' }}>
          <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
            Showing <strong>{totalFiltered}</strong> of {totalCount}
          </span>
          {hasActiveFilters && (
            <button
              className="btn btn-secondary"
              onClick={onResetFilters}
              style={{ padding: '3px 8px', fontSize: '11px' }}
              title="Reset all filters"
            >
              <RotateCcw size={11} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Active Filter Chips */}
      {hasActiveFilters && (
        <div className="filter-chips-row">
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Active filters:</span>
          {scope === 'dedup_fp' && (
            <span className="filter-chip" style={{ borderColor: 'var(--sev-medium-border)', background: 'var(--sev-medium-bg)' }}>
              Scope: Deduplicated / FP
              {onScopeChange && <X size={12} className="filter-chip-remove" onClick={() => onScopeChange('actionable')} />}
            </span>
          )}
          {scope === 'all' && (
            <span className="filter-chip">
              Scope: All Ingested
              {onScopeChange && <X size={12} className="filter-chip-remove" onClick={() => onScopeChange('actionable')} />}
            </span>
          )}
          {searchTerm && (
            <span className="filter-chip">
              Search: "{searchTerm}"
              <X size={12} className="filter-chip-remove" onClick={() => onSearchChange('')} />
            </span>
          )}
          {scannerFilter.map((s) => (
            <span key={s} className="filter-chip">
              Scanner: {s}
              <X size={12} className="filter-chip-remove" onClick={() => onScannerChange(scannerFilter.filter((x) => x !== s))} />
            </span>
          ))}
          {tierFilter.map((t) => (
            <span key={t} className="filter-chip">
              SLA: {t}
              <X size={12} className="filter-chip-remove" onClick={() => onTierChange(tierFilter.filter((x) => x !== t))} />
            </span>
          ))}
          {hostFilter.map((h) => (
            <span key={h} className="filter-chip">
              Host: {h}
              <X size={12} className="filter-chip-remove" onClick={() => onHostChange(hostFilter.filter((x) => x !== h))} />
            </span>
          ))}
          {kevOnly && (
            <span className="filter-chip" style={{ borderColor: 'var(--sev-critical-border)', background: 'var(--sev-critical-bg)' }}>
              KEV Active
              <X size={12} className="filter-chip-remove" onClick={() => onKevChange(false)} />
            </span>
          )}
          {minScore > 0 && (
            <span className="filter-chip">
              Score ≥ {minScore}
              <X size={12} className="filter-chip-remove" onClick={() => onMinScoreChange(0)} />
            </span>
          )}
        </div>
      )}
    </div>
  );
}

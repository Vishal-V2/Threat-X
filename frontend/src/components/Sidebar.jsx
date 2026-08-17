import React from 'react';
import Filters from './Filters';
import { Terminal } from 'lucide-react';

export default function Sidebar({
  scannerFilter,
  onScannerChange,
  tierFilter,
  onTierChange,
  hostFilter,
  onHostChange,
  availableHosts,
  kevOnly,
  onKevChange,
  minScore,
  onMinScoreChange,
  onResetFilters,
  scanId,
}) {
  return (
    <aside className="sidebar">
      <Filters
        scannerFilter={scannerFilter}
        onScannerChange={onScannerChange}
        tierFilter={tierFilter}
        onTierChange={onTierChange}
        hostFilter={hostFilter}
        onHostChange={onHostChange}
        availableHosts={availableHosts}
        kevOnly={kevOnly}
        onKevChange={onKevChange}
        minScore={minScore}
        onMinScoreChange={onMinScoreChange}
        onResetFilters={onResetFilters}
      />

      <div style={{ marginTop: 'auto', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <Terminal size={14} />
          <span>Threat-X Pipeline Engine</span>
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
          Scan Target: {scanId || '—'}
        </div>
      </div>
    </aside>
  );
}

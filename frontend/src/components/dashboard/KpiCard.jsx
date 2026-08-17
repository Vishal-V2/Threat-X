import React from 'react';

export default function KpiCard({ label, value, subtext, variant = 'primary' }) {
  return (
    <div className={`kpi-card accent-${variant}`}>
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{value ?? '—'}</span>
      {subtext && <span className="kpi-subtext">{subtext}</span>}
    </div>
  );
}

import React from 'react';

export default function MetricCard({ title, value, badgeText, badgeVariant = 'blue' }) {
  return (
    <div className="metric-card">
      <span className="metric-title">{title}</span>
      <span className="metric-value">{value ?? '—'}</span>
      {badgeText && (
        <span className={`metric-badge ${badgeVariant}`}>
          {badgeText}
        </span>
      )}
    </div>
  );
}

import React from 'react';

export function SlaBadge({ tier, isDuplicate, isSuppressed }) {
  if (isDuplicate) {
    return <span className="badge badge-info" style={{ background: 'var(--bg-surface-subtle)', color: 'var(--text-muted)' }}>Duplicate</span>;
  }
  if (isSuppressed) {
    return <span className="badge badge-medium" style={{ background: 'var(--sev-medium-bg)', color: 'var(--sev-medium)', borderColor: 'var(--sev-medium-border)' }}>Suppressed</span>;
  }
  if (!tier) return <span className="badge badge-info">—</span>;
  const t = tier.toLowerCase();
  let badgeClass = 'badge-info';
  if (t === 'critical') badgeClass = 'badge-critical';
  else if (t === 'high') badgeClass = 'badge-high';
  else if (t === 'medium') badgeClass = 'badge-medium';
  else if (t === 'low') badgeClass = 'badge-low';

  return <span className={`badge ${badgeClass}`}>{tier}</span>;
}

export function KevBadge({ active }) {
  if (!active) return <span style={{ color: 'var(--text-subtle)', fontSize: '11px' }}>No</span>;
  return <span className="badge badge-kev">KEV</span>;
}

export function ScoreBadge({ score }) {
  if (score == null) return <span>—</span>;
  const num = Number(score);
  let color = 'var(--text-main)';
  if (num >= 80) color = 'var(--sev-critical)';
  else if (num >= 60) color = 'var(--sev-high)';
  else if (num >= 40) color = 'var(--sev-medium)';
  else color = 'var(--primary)';

  return (
    <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color, fontSize: '12px' }}>
      {num.toFixed(1)}
    </span>
  );
}

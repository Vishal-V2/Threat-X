import React from 'react';

export default function KpiCard({
  label,
  value,
  subtext,
  variant = 'primary',
  onClick,
  ariaLabel,
}) {
  const isClickable = typeof onClick === 'function';

  return (
    <div
      role={isClickable ? 'button' : undefined}
      tabIndex={isClickable ? 0 : undefined}
      className={`kpi-card accent-${variant} ${isClickable ? 'clickable' : ''}`}
      onClick={onClick}
      onKeyDown={(e) => {
        if (isClickable && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
      aria-label={ariaLabel || (isClickable ? `Filter findings by ${label}` : undefined)}
    >
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{value ?? '—'}</span>
      {subtext && <span className="kpi-subtext">{subtext}</span>}
    </div>
  );
}

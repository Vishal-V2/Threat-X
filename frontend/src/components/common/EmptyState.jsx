import React from 'react';
import { Inbox, AlertCircle, RefreshCw } from 'lucide-react';

export function EmptyState({ title = 'No data found', message, actionText, onAction }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <Inbox size={36} strokeWidth={1.5} color="var(--border-strong)" style={{ marginBottom: '12px' }} />
      <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>{title}</h4>
      {message && <p style={{ fontSize: '12px', maxWidth: '380px', marginBottom: '16px' }}>{message}</p>}
      {actionText && onAction && (
        <button className="btn btn-secondary" onClick={onAction}>
          {actionText}
        </button>
      )}
    </div>
  );
}

export function ErrorState({ title = 'Unable to load data', message, onRetry }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <AlertCircle size={36} color="var(--sev-critical)" style={{ marginBottom: '12px' }} />
      <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>{title}</h4>
      {message && <p style={{ fontSize: '12px', maxWidth: '420px', marginBottom: '16px' }}>{message}</p>}
      {onRetry && (
        <button className="btn btn-secondary" onClick={onRetry}>
          <RefreshCw size={13} style={{ marginRight: '4px' }} />
          Retry
        </button>
      )}
    </div>
  );
}

export function TableSkeleton({ rows = 5 }) {
  return (
    <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          style={{
            height: '24px',
            backgroundColor: 'var(--bg-surface-subtle)',
            borderRadius: '4px',
            animation: 'pulse 1.5s infinite ease-in-out',
          }}
        />
      ))}
    </div>
  );
}

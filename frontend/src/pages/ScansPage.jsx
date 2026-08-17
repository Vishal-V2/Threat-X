import React, { useState } from 'react';
import { Radar, CheckCircle2, ArrowRight, Plus } from 'lucide-react';
import LaunchScanModal from '../components/scans/LaunchScanModal';

export default function ScansPage({
  scans = [],
  selectedScanId,
  onSelectScan,
  onNavigate,
  onScanCompleted,
}) {
  const [showModal, setShowModal] = useState(false);

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">Scan History & Orchestration</h2>
          <p className="page-subtitle">
            Historical pipeline runs processed with deterministic deduplication and scoring
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => setShowModal(true)}
          style={{ padding: '6px 12px', fontSize: '12px' }}
        >
          <Plus size={14} />
          <span>Launch New Scan</span>
        </button>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Radar size={15} color="var(--primary)" />
            <span>Available Security Scans ({scans.length})</span>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="enterprise-table">
            <thead>
              <tr>
                <th>Scan Identifier</th>
                <th>Completed</th>
                <th>Raw Inputs</th>
                <th>Duplicates Removed</th>
                <th>Actionable Findings</th>
                <th>Noise Reduction</th>
                <th>Status</th>
                <th style={{ width: '100px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const isCurrent = s.scan_id === selectedScanId;
                return (
                  <tr
                    key={s.scan_id}
                    className={isCurrent ? 'active-row' : ''}
                    onClick={() => onSelectScan(s.scan_id)}
                  >
                    <td style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span>{s.scan_id}</span>
                        {s.is_latest && (
                          <span className="badge badge-info" style={{ fontSize: '9.5px', padding: '1px 4px' }}>
                            LATEST
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {s.completed_at ? new Date(s.completed_at).toLocaleString() : '—'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {s.raw_count ?? '—'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--sev-medium)' }}>
                      {s.raw_count != null && s.final_count != null ? s.raw_count - s.final_count : '—'}
                    </td>
                    <td style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--primary)' }}>
                      {s.final_count ?? '—'}
                    </td>
                    <td>
                      {s.noise_reduction_pct != null ? (
                        <span style={{ fontWeight: 600, color: '#16a34a', background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '1px 6px', borderRadius: '3px', fontSize: '11px' }}>
                          -{s.noise_reduction_pct}%
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#16a34a', fontSize: '11.5px', fontWeight: 500 }}>
                        <CheckCircle2 size={13} />
                        <span>Scored & Ready</span>
                      </div>
                    </td>
                    <td>
                      <button
                        className={`btn ${isCurrent ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ padding: '2px 8px', fontSize: '11px' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectScan(s.scan_id);
                          onNavigate('findings');
                        }}
                      >
                        <span>{isCurrent ? 'Viewing' : 'Inspect'}</span>
                        <ArrowRight size={11} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Launch Scan Modal */}
      <LaunchScanModal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        onScanCompleted={(newScanId) => {
          if (onScanCompleted) onScanCompleted(newScanId);
        }}
      />
    </div>
  );
}

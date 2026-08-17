import React, { useState, useEffect } from 'react';
import { X, Play, Loader2, AlertCircle, CheckCircle2, Globe, Cpu, Zap } from 'lucide-react';
import { api } from '../../services/api';

export default function LaunchScanModal({ isOpen, onClose, onScanCompleted }) {
  const [scanId, setScanId] = useState('');
  const [mode, setMode] = useState('fixtures'); // 'live' or 'fixtures'
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [fast, setFast] = useState(true);
  const [loading, setLoading] = useState(false);
  const [jobStatus, setJobStatus] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      const now = new Date();
      const defaultId = `scan-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
      setScanId(defaultId);
      setJobStatus(null);
      setError(null);
      setLoading(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleLaunch = async (e) => {
    e.preventDefault();
    if (!scanId.trim()) {
      setError('Scan identifier is required.');
      return;
    }

    if (mode === 'live' && !targetUrl.trim()) {
      setError('Target URL is required for live multi-scanner scanning.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const payload = {
        scan_id: scanId.trim(),
        target_url: mode === 'live' ? targetUrl.trim() : null,
        use_fixtures: mode === 'fixtures',
        fast: fast,
      };

      const res = await api.launchScan(payload);
      setJobStatus(res);

      // Start status polling
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await api.getScanStatus(scanId.trim());
          setJobStatus(statusRes);

          if (statusRes.status === 'completed') {
            clearInterval(pollInterval);
            setLoading(false);
            setTimeout(() => {
              if (onScanCompleted) onScanCompleted(scanId.trim());
              onClose();
            }, 1200);
          } else if (statusRes.status === 'failed') {
            clearInterval(pollInterval);
            setLoading(false);
            setError(statusRes.error || 'Scan pipeline execution failed.');
          }
        } catch (pollErr) {
          clearInterval(pollInterval);
          setLoading(false);
          setError(pollErr.message);
        }
      }, 1500);

    } catch (err) {
      setLoading(false);
      setError(err.message || 'Failed to start scan.');
    }
  };

  return (
    <div className="drawer-backdrop" onClick={loading ? undefined : onClose}>
      <div
        className="card"
        style={{
          width: '520px',
          maxWidth: '92vw',
          margin: 'auto',
          backgroundColor: 'var(--bg-surface)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-header" style={{ padding: '14px 18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={16} color="var(--primary)" />
            <span style={{ fontWeight: 700, fontSize: '14px' }}>Launch Security Scan Pipeline</span>
          </div>
          {!loading && (
            <button onClick={onClose} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
              <X size={18} />
            </button>
          )}
        </div>

        <form onSubmit={handleLaunch} style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Scan ID */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Scan Identifier
            </label>
            <input
              type="text"
              className="filter-search-input"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              disabled={loading}
              placeholder="e.g. prod-scan-01"
              style={{ fontFamily: 'var(--font-mono)' }}
            />
          </div>

          {/* Mode Selection */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Execution Mode
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <button
                type="button"
                className={`btn ${mode === 'fixtures' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setMode('fixtures')}
                disabled={loading}
                style={{ padding: '8px 12px', justifyContent: 'flex-start', textAlign: 'left' }}
              >
                <Cpu size={14} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '11.5px' }}>Simulation / Demo</div>
                  <div style={{ fontSize: '10px', opacity: 0.8 }}>Fast fixture ingest</div>
                </div>
              </button>

              <button
                type="button"
                className={`btn ${mode === 'live' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setMode('live')}
                disabled={loading}
                style={{ padding: '8px 12px', justifyContent: 'flex-start', textAlign: 'left' }}
              >
                <Globe size={14} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '11.5px' }}>Live Target Scan</div>
                  <div style={{ fontSize: '10px', opacity: 0.8 }}>Nuclei + Nmap + ZAP</div>
                </div>
              </button>
            </div>
          </div>

          {/* Target URL if live */}
          {mode === 'live' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', background: 'var(--bg-surface-subtle)', padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-main)' }}>
                Target URL
              </label>
              <input
                type="url"
                className="filter-search-input"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={loading}
                placeholder="https://target.example.com"
                required
              />
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Requires Nuclei, Nmap, and Docker (for ZAP) installed and active on the host machine.
              </span>
            </div>
          )}

          {/* Fast mode checkbox */}
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-main)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={fast}
              onChange={(e) => setFast(e.target.checked)}
              disabled={loading}
              style={{ accentColor: 'var(--primary)' }}
            />
            <span>
              <strong>Fast Mode:</strong> Optimize scanner scope for speed & high-confidence checks
            </span>
          </label>

          {/* Progress / Status Display */}
          {jobStatus && (
            <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: '4px', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11.5px' }}>
                <span style={{ fontWeight: 600, textTransform: 'uppercase', color: 'var(--primary)' }}>
                  Stage: {jobStatus.progress_stage}
                </span>
                {loading && <Loader2 size={13} className="spinner" />}
                {jobStatus.status === 'completed' && <CheckCircle2 size={14} color="#16a34a" />}
              </div>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                {jobStatus.message}
              </span>
            </div>
          )}

          {/* Error display */}
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--sev-critical)', background: 'var(--sev-critical-bg)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--sev-critical-border)' }}>
              <AlertCircle size={14} />
              <span>{error}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 size={13} className="spinner" />
                  <span>Processing Pipeline...</span>
                </>
              ) : (
                <>
                  <Play size={13} fill="currentColor" />
                  <span>Execute Scan</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

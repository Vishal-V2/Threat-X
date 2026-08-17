import React, { useState, useEffect } from 'react';
import { ExternalLink, UserPlus, UserX, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { api } from '../../services/api';

export default function FindingTicket({ scanId, finding, onTicketUpdated }) {
  const [assignees, setAssignees] = useState([]);
  const [configured, setConfigured] = useState(true);
  const [loading, setLoading] = useState(false);
  const [usernameInput, setUsernameInput] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [toast, setToast] = useState({ type: '', text: '' });

  const issueNumber = finding?.github_issue_number;
  const issueUrl = finding?.github_issue_url;

  useEffect(() => {
    if (!finding || !issueNumber) return;

    let mounted = true;
    setLoading(true);
    setToast({ type: '', text: '' });

    api.getFindingTicket(scanId, finding.finding_id)
      .then((res) => {
        if (mounted) {
          setConfigured(res.github_configured);
          setAssignees(res.assignees || []);
        }
      })
      .catch((err) => {
        if (mounted) setToast({ type: 'error', text: err.message });
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => { mounted = false; };
  }, [scanId, finding?.finding_id, issueNumber]);

  if (!issueNumber) {
    return (
      <div style={{ padding: '10px 12px', background: 'var(--bg-surface-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', fontSize: '11.5px', color: 'var(--text-muted)' }}>
        No issue ticket created for this finding yet.
      </div>
    );
  }

  const handleAssign = async () => {
    const names = usernameInput.split(',').map((s) => s.trim()).filter(Boolean);
    if (!names.length) {
      setToast({ type: 'error', text: 'Enter at least one GitHub username.' });
      return;
    }

    setActionLoading(true);
    setToast({ type: '', text: '' });

    try {
      const res = await api.assignTicket(issueNumber, names);
      setAssignees(res.assignees || names);
      setUsernameInput('');
      setToast({ type: 'success', text: res.message });
      if (onTicketUpdated) onTicketUpdated();
    } catch (err) {
      setToast({ type: 'error', text: err.message });
    } finally {
      setActionLoading(false);
    }
  };

  const handleUnassign = async () => {
    setActionLoading(true);
    setToast({ type: '', text: '' });

    try {
      const res = await api.unassignTicket(issueNumber);
      setAssignees([]);
      setToast({ type: 'success', text: res.message });
      if (onTicketUpdated) onTicketUpdated();
    } catch (err) {
      setToast({ type: 'error', text: err.message });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', background: 'var(--bg-surface-subtle)', padding: '12px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 600, fontSize: '12px' }}>GitHub Issue #{issueNumber}</span>
          {issueUrl && (
            <a
              href={issueUrl}
              target="_blank"
              rel="noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', color: 'var(--primary)', textDecoration: 'none' }}
            >
              Open in GitHub <ExternalLink size={11} />
            </a>
          )}
        </div>
        {loading && <Loader2 size={13} className="spinner" />}
      </div>

      {!configured && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--sev-high)' }}>
          <AlertCircle size={13} />
          <span>Configure GITHUB_TOKEN & GITHUB_REPO in .env to enable ticket assignment.</span>
        </div>
      )}

      <div style={{ fontSize: '12px' }}>
        <span style={{ color: 'var(--text-muted)' }}>Assigned to: </span>
        {assignees.length > 0 ? (
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{assignees.join(', ')}</span>
        ) : (
          <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>None</span>
        )}
      </div>

      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="filter-search-input"
          placeholder="GitHub username(s)"
          value={usernameInput}
          onChange={(e) => setUsernameInput(e.target.value)}
          disabled={!configured || actionLoading}
          style={{ flex: 1, minWidth: '160px', padding: '4px 8px' }}
        />
        <button
          className="btn btn-primary"
          onClick={handleAssign}
          disabled={!configured || actionLoading}
          style={{ padding: '4px 8px' }}
        >
          {actionLoading ? <Loader2 size={12} className="spinner" /> : <UserPlus size={12} />}
          <span>Assign</span>
        </button>
        <button
          className="btn btn-secondary"
          onClick={handleUnassign}
          disabled={!configured || actionLoading || assignees.length === 0}
          style={{ padding: '4px 8px' }}
        >
          <UserX size={12} />
          <span>Unassign</span>
        </button>
      </div>

      {toast.text && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: toast.type === 'success' ? '#16a34a' : 'var(--sev-critical)' }}>
          {toast.type === 'success' ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
          <span>{toast.text}</span>
        </div>
      )}
    </div>
  );
}

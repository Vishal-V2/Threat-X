import React, { useState, useEffect } from 'react';
import { UserPlus, UserX, ExternalLink, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react';
import { api } from '../services/api';

export default function TicketAssignment({ scanId, finding, onTicketUpdated }) {
  const [assignees, setAssignees] = useState([]);
  const [configured, setConfigured] = useState(true);
  const [loadingTicket, setLoadingTicket] = useState(false);
  const [usernameInput, setUsernameInput] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [msg, setMsg] = useState({ type: '', text: '' });

  const issueNumber = finding?.github_issue_number;
  const issueUrl = finding?.github_issue_url;

  useEffect(() => {
    if (!finding || !issueNumber) return;

    let isMounted = true;
    setLoadingTicket(true);
    setMsg({ type: '', text: '' });

    api.getFindingTicket(scanId, finding.finding_id)
      .then((res) => {
        if (isMounted) {
          setConfigured(res.github_configured);
          setAssignees(res.assignees || []);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setMsg({ type: 'error', text: err.message });
        }
      })
      .finally(() => {
        if (isMounted) setLoadingTicket(false);
      });

    return () => {
      isMounted = false;
    };
  }, [scanId, finding?.finding_id, issueNumber]);

  if (!issueNumber) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontStyle: 'italic' }}>
        No ticket created yet for this finding — nothing to assign.
      </div>
    );
  }

  const handleAssign = async () => {
    const names = usernameInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    if (names.length === 0) {
      setMsg({ type: 'error', text: 'Enter at least one GitHub username first.' });
      return;
    }

    setActionLoading(true);
    setMsg({ type: '', text: '' });

    try {
      const res = await api.assignTicket(issueNumber, names);
      setAssignees(res.assignees || names);
      setUsernameInput('');
      setMsg({ type: 'success', text: res.message });
      if (onTicketUpdated) onTicketUpdated();
    } catch (err) {
      setMsg({ type: 'error', text: err.message });
    } finally {
      setActionLoading(false);
    }
  };

  const handleUnassign = async () => {
    setActionLoading(true);
    setMsg({ type: '', text: '' });

    try {
      const res = await api.unassignTicket(issueNumber);
      setAssignees([]);
      setMsg({ type: 'success', text: res.message });
      if (onTicketUpdated) onTicketUpdated();
    } catch (err) {
      setMsg({ type: 'error', text: err.message });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="ticket-box">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '0.85rem', fontWeight: '700' }}>GitHub Issue #{issueNumber}</span>
          {issueUrl && (
            <a
              href={issueUrl}
              target="_blank"
              rel="noreferrer"
              style={{ color: 'var(--accent-cyan)', display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '0.78rem' }}
            >
              View Ticket <ExternalLink size={12} />
            </a>
          )}
        </div>

        {loadingTicket && <Loader2 size={14} className="spinner" />}
      </div>

      {!configured && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#fb923c' }}>
          <AlertTriangle size={14} />
          <span>Set GITHUB_TOKEN / GITHUB_REPO in .env to enable live assignment.</span>
        </div>
      )}

      <div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Currently assigned: </span>
        {assignees.length > 0 ? (
          <span style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--accent-cyan)' }}>
            {assignees.join(', ')}
          </span>
        ) : (
          <span style={{ fontSize: '0.8rem', fontStyle: 'italic', color: 'var(--text-secondary)' }}>None</span>
        )}
      </div>

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="input-text"
          placeholder="GitHub username(s), comma-separated"
          value={usernameInput}
          onChange={(e) => setUsernameInput(e.target.value)}
          disabled={!configured || actionLoading}
        />
        <button
          className="btn btn-primary"
          onClick={handleAssign}
          disabled={!configured || actionLoading}
        >
          {actionLoading ? <Loader2 size={14} className="spinner" /> : <UserPlus size={14} />}
          <span>Assign</span>
        </button>
        <button
          className="btn btn-secondary"
          onClick={handleUnassign}
          disabled={!configured || actionLoading || assignees.length === 0}
        >
          <UserX size={14} />
          <span>Unassign all</span>
        </button>
      </div>

      {msg.text && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.75rem',
            padding: '6px 10px',
            borderRadius: '4px',
            background: msg.type === 'success' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            color: msg.type === 'success' ? '#4ade80' : '#f87171',
            border: `1px solid ${msg.type === 'success' ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          }}
        >
          {msg.type === 'success' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          <span>{msg.text}</span>
        </div>
      )}
    </div>
  );
}

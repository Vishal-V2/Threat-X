/**
 * Threat-X API Service layer
 * Communicates with FastAPI backend for scans, findings, and ticket workflows.
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function fetchJson(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch (_) {
      // fallback to status text
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  /**
   * Health check endpoint
   */
  async getHealth() {
    return fetchJson('/api/health');
  },

  /**
   * Get all completed scans sorted newest first
   */
  async getScans() {
    return fetchJson('/api/scans');
  },

  /**
   * Get metrics and detail for a single scan
   */
  async getScan(scanId) {
    return fetchJson(`/api/scans/${encodeURIComponent(scanId)}`);
  },

  /**
   * Get all findings for a scan
   */
  async getFindings(scanId) {
    return fetchJson(`/api/scans/${encodeURIComponent(scanId)}/findings`);
  },

  /**
   * Launch a new scan pipeline run (live or fixture simulation)
   */
  async launchScan(payload) {
    return fetchJson('/api/scans/run', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Check status of a running scan job
   */
  async getScanStatus(scanId) {
    return fetchJson(`/api/scans/status/${encodeURIComponent(scanId)}`);
  },

  /**
   * Get GitHub ticket status and assignees for a finding
   */
  async getFindingTicket(scanId, findingId) {
    return fetchJson(`/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/ticket`);
  },

  /**
   * Assign GitHub issue to usernames
   */
  async assignTicket(issueNumber, usernames) {
    return fetchJson(`/api/tickets/${issueNumber}/assign`, {
      method: 'POST',
      body: JSON.stringify({ usernames }),
    });
  },

  /**
   * Unassign all users from GitHub issue
   */
  async unassignTicket(issueNumber) {
    return fetchJson(`/api/tickets/${issueNumber}/unassign`, {
      method: 'POST',
    });
  },
};

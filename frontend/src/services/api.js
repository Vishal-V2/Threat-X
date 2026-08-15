const API_BASE = '/api';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function fetchScans() {
  const res = await fetch(`${API_BASE}/scans`);
  if (!res.ok) throw new Error(`Failed to load scans: ${res.statusText}`);
  const data = await res.json();
  return data.scans || [];
}

export async function fetchScanDetails(scanId) {
  const res = await fetch(`${API_BASE}/scan/${encodeURIComponent(scanId)}`);
  if (!res.ok) throw new Error(`Failed to load scan details for ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function triggerScan(scanId = 'demo', useFixtures = true) {
  const res = await fetch(`${API_BASE}/scan/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_id: scanId, use_fixtures: useFixtures }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan trigger failed: ${res.statusText}`);
  }
  return res.json();
}

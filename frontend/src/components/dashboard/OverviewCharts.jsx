import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';

const SLA_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
};

const SCANNER_COLORS = {
  nuclei: '#2563eb',
  nmap: '#ea580c',
  zap: '#059669',
};

export function SlaDistributionChart({ actionableFindings = [] }) {
  const tierOrder = ['critical', 'high', 'medium', 'low'];
  const counts = actionableFindings.reduce((acc, f) => {
    const tier = (f.sla_tier || '').toLowerCase();
    if (tier) acc[tier] = (acc[tier] || 0) + 1;
    return acc;
  }, {});

  const data = tierOrder.map((tier) => ({
    name: tier,
    count: counts[tier] || 0,
  }));

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Remediation SLA Distribution</span>
      </div>
      <div className="card-body" style={{ height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
            <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '4px', fontSize: '11px', color: '#0f172a', boxShadow: '0 2px 4px rgba(0,0,0,0.08)' }}
              formatter={(val) => [`${val} findings`, 'Actionable']}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={SLA_COLORS[entry.name] || '#64748b'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function ScannerDistributionChart({ allFindings = [] }) {
  const counts = allFindings.reduce((acc, f) => {
    const scanner = f.source_scanner || 'unknown';
    acc[scanner] = (acc[scanner] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts).map(([name, count]) => ({ name, count }));

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Raw Scanner Output</span>
      </div>
      <div className="card-body" style={{ height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
            <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '4px', fontSize: '11px', color: '#0f172a', boxShadow: '0 2px 4px rgba(0,0,0,0.08)' }}
              formatter={(val) => [`${val} findings`, 'Raw Ingest']}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={SCANNER_COLORS[entry.name.toLowerCase()] || '#64748b'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export function ScannerOverlapChart({ actionableFindings = [] }) {
  const counts = actionableFindings.reduce((acc, f) => {
    const label = f.contributing_label || f.source_scanner || 'unknown';
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.count - b.count);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Contributing Scanner Overlap</span>
      </div>
      <div className="card-body" style={{ height: Math.max(160, data.length * 36) }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart layout="vertical" data={data} margin={{ top: 5, right: 20, left: 100, bottom: 5 }}>
            <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} allowDecimals={false} />
            <YAxis type="category" dataKey="name" stroke="#0f172a" fontSize={11} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} width={110} />
            <Tooltip
              contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '4px', fontSize: '11px', color: '#0f172a', boxShadow: '0 2px 4px rgba(0,0,0,0.08)' }}
              formatter={(val) => [`${val} findings`, 'Actionable']}
            />
            <Bar dataKey="count" fill="#475569" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

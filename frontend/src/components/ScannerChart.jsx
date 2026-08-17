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

const SCANNER_COLORS = {
  nuclei: '#2a78d6',
  nmap: '#eb6834',
  zap: '#1baf7a',
};

export default function ScannerChart({ allFindings = [] }) {
  // Aggregate by raw scanner
  const counts = allFindings.reduce((acc, f) => {
    const scanner = f.source_scanner || 'unknown';
    acc[scanner] = (acc[scanner] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts).map(([name, count]) => ({
    name,
    count,
  }));

  return (
    <div className="chart-card">
      <h4 style={{ fontSize: '0.95rem', fontWeight: '700', fontFamily: 'var(--font-heading)' }}>
        Raw Findings by Scanner
      </h4>
      <div style={{ width: '100%', height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis
              dataKey="name"
              stroke="#94a3b8"
              fontSize={12}
              tickLine={false}
              axisLine={{ stroke: '#243049' }}
            />
            <YAxis
              stroke="#64748b"
              fontSize={12}
              tickLine={false}
              axisLine={{ stroke: '#243049' }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#111827',
                borderColor: '#243049',
                borderRadius: '8px',
                color: '#f1f5f9',
                fontSize: '12px',
              }}
              formatter={(val) => [`${val} findings`, 'Raw count']}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell
                  key={`scanner-${entry.name}`}
                  fill={SCANNER_COLORS[entry.name.toLowerCase()] || '#898781'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

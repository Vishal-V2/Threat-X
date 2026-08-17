import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';

export default function ScannerOverlap({ actionableFindings = [] }) {
  const counts = actionableFindings.reduce((acc, f) => {
    const label = f.contributing_label || f.source_scanner || 'unknown';
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});

  const data = Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.count - b.count);

  return (
    <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
      <h4 style={{ fontSize: '0.95rem', fontWeight: '700', fontFamily: 'var(--font-heading)' }}>
        Scanner Overlap on Final Findings
      </h4>
      <div style={{ width: '100%', height: Math.max(180, data.length * 45) }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            layout="vertical"
            data={data}
            margin={{ top: 10, right: 20, left: 120, bottom: 10 }}
          >
            <XAxis
              type="number"
              stroke="#64748b"
              fontSize={12}
              tickLine={false}
              axisLine={{ stroke: '#243049' }}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              stroke="#94a3b8"
              fontSize={12}
              tickLine={false}
              axisLine={{ stroke: '#243049' }}
              width={130}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#111827',
                borderColor: '#243049',
                borderRadius: '8px',
                color: '#f1f5f9',
                fontSize: '12px',
              }}
              formatter={(val) => [`${val} findings`, 'Overlap count']}
            />
            <Bar dataKey="count" fill="#52514e" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

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

export default function ScoreBreakdown({ breakdown }) {
  if (!breakdown || typeof breakdown !== 'object') {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '0.82rem', padding: '16px', textAlign: 'center' }}>
        No score breakdown available for this finding.
      </div>
    );
  }

  // Filter out internal fields
  const data = Object.entries(breakdown)
    .filter(([key]) => key !== 'raw_total_before_clip' && key !== 'final_score')
    .map(([key, value]) => ({
      name: key.replace(/_/g, ' '),
      points: typeof value === 'number' ? Number(value.toFixed(2)) : Number(value || 0),
    }));

  return (
    <div style={{ width: '100%', height: 220 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          layout="vertical"
          data={data}
          margin={{ top: 10, right: 20, left: 100, bottom: 5 }}
        >
          <XAxis
            type="number"
            stroke="#64748b"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#243049' }}
          />
          <YAxis
            type="category"
            dataKey="name"
            stroke="#94a3b8"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#243049' }}
            width={110}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              borderColor: '#243049',
              borderRadius: '8px',
              color: '#f1f5f9',
              fontSize: '12px',
            }}
            formatter={(val) => [`${val} pts`, 'Score contribution']}
          />
          <Bar dataKey="points" fill="#2a78d6" radius={[0, 4, 4, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill="#2a78d6" />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

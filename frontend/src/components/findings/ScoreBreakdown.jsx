import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';

export default function ScoreBreakdown({ breakdown }) {
  if (!breakdown || typeof breakdown !== 'object') {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '11.5px', padding: '8px 0' }}>
        No score breakdown available.
      </div>
    );
  }

  const data = Object.entries(breakdown)
    .filter(([k]) => k !== 'raw_total_before_clip' && k !== 'final_score')
    .map(([k, v]) => ({
      name: k.replace(/_/g, ' '),
      points: typeof v === 'number' ? Number(v.toFixed(1)) : Number(v || 0),
    }));

  return (
    <div style={{ width: '100%', height: 160 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart layout="vertical" data={data} margin={{ top: 5, right: 15, left: 90, bottom: 5 }}>
          <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
          <YAxis type="category" dataKey="name" stroke="#0f172a" fontSize={10.5} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} width={95} />
          <Tooltip
            contentStyle={{ backgroundColor: '#ffffff', borderColor: '#cbd5e1', borderRadius: '4px', fontSize: '11px', color: '#0f172a' }}
            formatter={(val) => [`+${val} pts`, 'Weight contribution']}
          />
          <Bar dataKey="points" fill="#2563eb" radius={[0, 2, 2, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

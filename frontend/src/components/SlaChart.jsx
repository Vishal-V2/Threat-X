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
  critical: '#d03b3b',
  high: '#ec835a',
  medium: '#fab219',
  low: '#0ca30c',
};

export default function SlaChart({ actionableFindings = [] }) {
  const tierOrder = ['critical', 'high', 'medium', 'low'];

  const counts = actionableFindings.reduce((acc, f) => {
    const tier = (f.sla_tier || '').toLowerCase();
    if (tier) {
      acc[tier] = (acc[tier] || 0) + 1;
    }
    return acc;
  }, {});

  const data = tierOrder.map((tier) => ({
    name: tier,
    count: counts[tier] || 0,
  }));

  return (
    <div className="chart-card">
      <h4 style={{ fontSize: '0.95rem', fontWeight: '700', fontFamily: 'var(--font-heading)' }}>
        Final Ranked Findings by SLA Tier
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
              formatter={(val) => [`${val} findings`, 'Actionable count']}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell
                  key={`sla-${entry.name}`}
                  fill={SLA_COLORS[entry.name] || '#898781'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

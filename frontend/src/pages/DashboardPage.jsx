import React from 'react';
import KpiCard from '../components/dashboard/KpiCard';
import PriorityFindings from '../components/dashboard/PriorityFindings';
import {
  SlaDistributionChart,
  ScannerDistributionChart,
  ScannerOverlapChart,
} from '../components/dashboard/OverviewCharts';
import FindingDrawer from '../components/findings/FindingDrawer';

export default function DashboardPage({
  scanId,
  scanData,
  allFindings = [],
  actionableFindings = [],
  onNavigate,
  selectedFinding,
  onSelectFinding,
  onCloseFinding,
  onTicketUpdated,
}) {
  const metrics = scanData.metrics || {};
  const criticalCount = actionableFindings.filter((f) => (f.sla_tier || '').toLowerCase() === 'critical').length;
  const highCount = actionableFindings.filter((f) => (f.sla_tier || '').toLowerCase() === 'high').length;
  const kevCount = actionableFindings.filter((f) => f.in_kev).length;

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">Executive Risk Overview</h2>
          <p className="page-subtitle">
            Prioritized vulnerability posture for scan <code style={{ fontFamily: 'var(--font-mono)' }}>{scanId}</code>
          </p>
        </div>
      </div>

      {/* Operational KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          label="Actionable Findings"
          value={metrics.final_count ?? actionableFindings.length}
          subtext={`-${metrics.noise_reduction_pct ?? 0}% noise reduction`}
          variant="primary"
        />
        <KpiCard
          label="Critical Severity"
          value={criticalCount}
          subtext={criticalCount > 0 ? `${criticalCount} immediate remediation` : 'None identified'}
          variant="critical"
        />
        <KpiCard
          label="CISA KEV Active"
          value={kevCount}
          subtext={kevCount > 0 ? `${kevCount} in wild exploitation` : 'No active exploits'}
          variant="critical"
        />
        <KpiCard
          label="High Severity"
          value={highCount}
          subtext={`${highCount} SLA action required`}
          variant="high"
        />
        <KpiCard
          label="Deduplicated / FP"
          value={(metrics.duplicate_count ?? 0) + (metrics.suppressed_count ?? 0)}
          subtext={`${metrics.raw_count ?? allFindings.length} raw scanner inputs`}
          variant="medium"
        />
      </section>

      {/* Main Content Layout */}
      <div className="overview-two-col">
        {/* Priority Findings Action List */}
        <PriorityFindings
          findings={actionableFindings}
          onSelectFinding={onSelectFinding}
          onViewAll={() => onNavigate('findings')}
        />

        {/* SLA Distribution */}
        <SlaDistributionChart actionableFindings={actionableFindings} />
      </div>

      {/* Scanner Breakdown & Overlap */}
      <div className="charts-row">
        <ScannerDistributionChart allFindings={allFindings} />
        <ScannerOverlapChart actionableFindings={actionableFindings} />
      </div>

      {/* Slide-out Finding Detail Drawer */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          onClose={onCloseFinding}
          scanId={scanId}
          onTicketUpdated={onTicketUpdated}
        />
      )}
    </div>
  );
}

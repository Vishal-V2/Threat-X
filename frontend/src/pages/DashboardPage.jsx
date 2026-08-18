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
  onKpiClick,
  selectedFinding,
  onSelectFinding,
  onCloseFinding,
  onTicketUpdated,
}) {
  const metrics = scanData.metrics || {};
  const criticalCount = actionableFindings.filter((f) => (f.sla_tier || '').toLowerCase() === 'critical').length;
  const highCount = actionableFindings.filter((f) => (f.sla_tier || '').toLowerCase() === 'high').length;
  const kevCount = actionableFindings.filter((f) => f.in_kev).length;
  const dedupFpCount = (metrics.duplicate_count ?? 0) + (metrics.suppressed_count ?? 0);

  const handleKpiCardClick = (kpiType) => {
    if (onKpiClick) {
      onKpiClick(kpiType);
    } else if (onNavigate) {
      onNavigate('findings');
    }
  };

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
          onClick={() => handleKpiCardClick('actionable')}
          ariaLabel={`View ${metrics.final_count ?? actionableFindings.length} actionable findings`}
        />
        <KpiCard
          label="Critical Severity"
          value={criticalCount}
          subtext={criticalCount > 0 ? `${criticalCount} immediate remediation` : 'None identified'}
          variant="critical"
          onClick={() => handleKpiCardClick('critical')}
          ariaLabel={`View ${criticalCount} critical severity findings`}
        />
        <KpiCard
          label="CISA KEV Active"
          value={kevCount}
          subtext={kevCount > 0 ? `${kevCount} in wild exploitation` : 'No active exploits'}
          variant="critical"
          onClick={() => handleKpiCardClick('kev')}
          ariaLabel={`View ${kevCount} CISA KEV active findings`}
        />
        <KpiCard
          label="High Severity"
          value={highCount}
          subtext={`${highCount} SLA action required`}
          variant="high"
          onClick={() => handleKpiCardClick('high')}
          ariaLabel={`View ${highCount} high severity findings`}
        />
        <KpiCard
          label="Deduplicated / FP"
          value={dedupFpCount}
          subtext={`${metrics.raw_count ?? allFindings.length} raw scanner inputs`}
          variant="medium"
          onClick={() => handleKpiCardClick('dedup_fp')}
          ariaLabel={`View ${dedupFpCount} deduplicated and false positive findings`}
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

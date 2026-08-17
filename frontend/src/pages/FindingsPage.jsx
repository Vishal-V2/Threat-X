import React, { useState, useMemo } from 'react';
import FindingFilters from '../components/findings/FindingFilters';
import FindingsTable from '../components/findings/FindingsTable';
import FindingDrawer from '../components/findings/FindingDrawer';

export default function FindingsPage({
  scanId,
  findings = [],
  selectedFinding,
  onSelectFinding,
  onCloseFinding,
  onTicketUpdated,
}) {
  // Actionable findings
  const actionableFindings = useMemo(() => {
    return findings.filter((f) => !f.is_duplicate && !f.suppressed);
  }, [findings]);

  // Unique hosts
  const availableHosts = useMemo(() => {
    const hosts = Array.from(new Set(actionableFindings.map((f) => f.host).filter(Boolean)));
    return hosts.sort();
  }, [actionableFindings]);

  // Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [scannerFilter, setScannerFilter] = useState([]);
  const [tierFilter, setTierFilter] = useState([]);
  const [hostFilter, setHostFilter] = useState([]);
  const [kevOnly, setKevOnly] = useState(false);
  const [minScore, setMinScore] = useState(0);

  // Filtered dataset
  const filteredFindings = useMemo(() => {
    let result = actionableFindings;

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter((f) => {
        return (
          (f.title && f.title.toLowerCase().includes(term)) ||
          (f.host && f.host.toLowerCase().includes(term)) ||
          (f.owner && f.owner.toLowerCase().includes(term)) ||
          (f.cve_ids && f.cve_ids.some((c) => c.toLowerCase().includes(term))) ||
          (f.contributing_label && f.contributing_label.toLowerCase().includes(term)) ||
          (f.finding_id && f.finding_id.toLowerCase().includes(term))
        );
      });
    }

    if (scannerFilter.length > 0) {
      result = result.filter((f) => {
        const label = f.contributing_label || f.source_scanner || '';
        const parts = label.split(' + ');
        return scannerFilter.some((sc) => parts.includes(sc));
      });
    }

    if (tierFilter.length > 0) {
      result = result.filter((f) => tierFilter.includes((f.sla_tier || '').toLowerCase()));
    }

    if (hostFilter.length > 0) {
      result = result.filter((f) => hostFilter.includes(f.host));
    }

    if (kevOnly) {
      result = result.filter((f) => Boolean(f.in_kev));
    }

    if (minScore > 0) {
      result = result.filter((f) => (f.risk_score || 0) >= minScore);
    }

    return result;
  }, [actionableFindings, searchTerm, scannerFilter, tierFilter, hostFilter, kevOnly, minScore]);

  const handleResetFilters = () => {
    setSearchTerm('');
    setScannerFilter([]);
    setTierFilter([]);
    setHostFilter([]);
    setKevOnly(false);
    setMinScore(0);
  };

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">Actionable Findings</h2>
          <p className="page-subtitle">
            Deduplicated, enriched, and risk-ranked vulnerability backlog
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <FindingFilters
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        scannerFilter={scannerFilter}
        onScannerChange={setScannerFilter}
        tierFilter={tierFilter}
        onTierChange={setTierFilter}
        hostFilter={hostFilter}
        onHostChange={setHostFilter}
        availableHosts={availableHosts}
        kevOnly={kevOnly}
        onKevChange={setKevOnly}
        minScore={minScore}
        onMinScoreChange={setMinScore}
        onResetFilters={handleResetFilters}
        totalFiltered={filteredFindings.length}
        totalCount={actionableFindings.length}
      />

      {/* Dense Enterprise Table */}
      <FindingsTable
        findings={filteredFindings}
        selectedFindingId={selectedFinding?.finding_id}
        onSelectFinding={onSelectFinding}
      />

      {/* Slide-out Finding Drawer */}
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

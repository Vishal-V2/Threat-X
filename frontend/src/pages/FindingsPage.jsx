import React, { useState, useMemo, useEffect } from 'react';
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
  initialFilter,
  onFilterChange,
}) {
  // Filter state
  const [scope, setScope] = useState(initialFilter?.scope || 'actionable');
  const [searchTerm, setSearchTerm] = useState(initialFilter?.search || '');
  const [scannerFilter, setScannerFilter] = useState(initialFilter?.scanner ? [initialFilter.scanner] : []);
  const [tierFilter, setTierFilter] = useState(initialFilter?.tier ? [initialFilter.tier.toLowerCase()] : []);
  const [hostFilter, setHostFilter] = useState(initialFilter?.host ? [initialFilter.host] : []);
  const [kevOnly, setKevOnly] = useState(Boolean(initialFilter?.kev));
  const [minScore, setMinScore] = useState(initialFilter?.minScore || 0);

  // Synchronize when initialFilter prop changes (e.g., user clicked a KPI card)
  useEffect(() => {
    if (initialFilter) {
      setScope(initialFilter.scope || 'actionable');
      setSearchTerm(initialFilter.search || '');
      setScannerFilter(initialFilter.scanner ? [initialFilter.scanner] : []);
      setTierFilter(initialFilter.tier ? [initialFilter.tier.toLowerCase()] : []);
      setHostFilter(initialFilter.host ? [initialFilter.host] : []);
      setKevOnly(Boolean(initialFilter.kev));
      setMinScore(initialFilter.minScore || 0);
    }
  }, [initialFilter]);

  // Scoped dataset (Actionable vs Deduplicated/FP vs All)
  const scopedFindings = useMemo(() => {
    if (scope === 'dedup_fp') {
      return findings.filter((f) => f.is_duplicate || f.suppressed);
    }
    if (scope === 'all') {
      return findings;
    }
    return findings.filter((f) => !f.is_duplicate && !f.suppressed);
  }, [findings, scope]);

  // Unique hosts in current scope
  const availableHosts = useMemo(() => {
    const hosts = Array.from(new Set(scopedFindings.map((f) => f.host).filter(Boolean)));
    return hosts.sort();
  }, [scopedFindings]);

  // Filtered dataset
  const filteredFindings = useMemo(() => {
    let result = scopedFindings;

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
  }, [scopedFindings, searchTerm, scannerFilter, tierFilter, hostFilter, kevOnly, minScore]);

  const handleResetFilters = () => {
    setScope('actionable');
    setSearchTerm('');
    setScannerFilter([]);
    setTierFilter([]);
    setHostFilter([]);
    setKevOnly(false);
    setMinScore(0);
    if (onFilterChange) {
      onFilterChange({});
    }
  };

  const getPageTitle = () => {
    if (scope === 'dedup_fp') return 'Deduplicated & Suppressed Findings';
    if (scope === 'all') return 'All Ingested Findings';
    return 'Actionable Findings';
  };

  const getPageSubtitle = () => {
    if (scope === 'dedup_fp') {
      return 'Scanner noise eliminated via normalization, deduplication, and suppression passes';
    }
    if (scope === 'all') {
      return 'Complete multi-scanner dataset before and after deduplication';
    }
    return 'Deduplicated, enriched, and risk-ranked vulnerability backlog';
  };

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">{getPageTitle()}</h2>
          <p className="page-subtitle">{getPageSubtitle()}</p>
        </div>
      </div>

      {/* Filter Bar */}
      <FindingFilters
        searchTerm={searchTerm}
        onSearchChange={(val) => { setSearchTerm(val); if (onFilterChange) onFilterChange({ search: val }); }}
        scannerFilter={scannerFilter}
        onScannerChange={(val) => { setScannerFilter(val); if (onFilterChange) onFilterChange({ scanner: val[0] }); }}
        tierFilter={tierFilter}
        onTierChange={(val) => { setTierFilter(val); if (onFilterChange) onFilterChange({ tier: val[0] }); }}
        hostFilter={hostFilter}
        onHostChange={(val) => { setHostFilter(val); if (onFilterChange) onFilterChange({ host: val[0] }); }}
        availableHosts={availableHosts}
        kevOnly={kevOnly}
        onKevChange={(val) => { setKevOnly(val); if (onFilterChange) onFilterChange({ kev: val ? true : undefined }); }}
        minScore={minScore}
        onMinScoreChange={(val) => { setMinScore(val); if (onFilterChange) onFilterChange({ minScore: val || undefined }); }}
        scope={scope}
        onScopeChange={(val) => { setScope(val); if (onFilterChange) onFilterChange({ scope: val }); }}
        onResetFilters={handleResetFilters}
        totalFiltered={filteredFindings.length}
        totalCount={scopedFindings.length}
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

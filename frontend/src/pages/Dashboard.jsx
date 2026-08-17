import React, { useState, useEffect, useMemo, useCallback } from 'react';
import Header from '../components/Header';
import Sidebar from '../components/Sidebar';
import MetricCard from '../components/MetricCard';
import FindingsTable from '../components/FindingsTable';
import FindingDetail from '../components/FindingDetail';
import ScannerChart from '../components/ScannerChart';
import SlaChart from '../components/SlaChart';
import ScannerOverlap from '../components/ScannerOverlap';
import { api } from '../services/api';
import { AlertCircle, Layers, ShieldCheck, Loader2 } from 'lucide-react';

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [scanData, setScanData] = useState({ metrics: {} });
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Filters state
  const [scannerFilter, setScannerFilter] = useState([]);
  const [tierFilter, setTierFilter] = useState([]);
  const [hostFilter, setHostFilter] = useState([]);
  const [kevOnly, setKevOnly] = useState(false);
  const [minScore, setMinScore] = useState(0);

  // Loading & Error state
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingScanData, setLoadingScanData] = useState(false);
  const [error, setError] = useState(null);

  // Fetch scans list
  const fetchScans = useCallback(async (preserveSelected = true) => {
    try {
      setLoadingScans(true);
      setError(null);
      const res = await api.getScans();
      const list = res.scans || [];
      setScans(list);

      if (list.length > 0) {
        if (!preserveSelected || !selectedScanId || !list.some((s) => s.scan_id === selectedScanId)) {
          setSelectedScanId(list[0].scan_id);
        }
      } else {
        setSelectedScanId('');
      }
    } catch (err) {
      setError(err.message || 'Unable to connect to Threat-X backend.');
    } finally {
      setLoadingScans(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    fetchScans(false);
  }, []);

  // Fetch scan detail & findings when selectedScanId changes
  const loadScanDetails = useCallback(async () => {
    if (!selectedScanId) return;

    try {
      setLoadingScanData(true);
      setError(null);

      const [scanRes, findingsRes] = await Promise.all([
        api.getScan(selectedScanId),
        api.getFindings(selectedScanId),
      ]);

      setScanData(scanRes || { metrics: {} });
      const findingList = findingsRes.findings || [];
      setFindings(findingList);

      // Select top actionable finding by default
      const actionable = findingList.filter((f) => !f.is_duplicate && !f.suppressed);
      if (actionable.length > 0) {
        setSelectedFinding(actionable[0]);
      } else {
        setSelectedFinding(null);
      }
    } catch (err) {
      setError(err.message || `Unable to load scan "${selectedScanId}".`);
    } finally {
      setLoadingScanData(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    loadScanDetails();
  }, [loadScanDetails]);

  // Actionable findings
  const actionableFindings = useMemo(() => {
    return findings.filter((f) => !f.is_duplicate && !f.suppressed);
  }, [findings]);

  // Available unique hosts for filtering
  const availableHosts = useMemo(() => {
    const hosts = Array.from(new Set(actionableFindings.map((f) => f.host).filter(Boolean)));
    return hosts.sort();
  }, [actionableFindings]);

  // Filtered actionable findings
  const filteredFindings = useMemo(() => {
    let result = actionableFindings;

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

    // Sort descending by risk score
    return [...result].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  }, [actionableFindings, scannerFilter, tierFilter, hostFilter, kevOnly, minScore]);

  // Keep selected finding in sync with filtered items if possible
  useEffect(() => {
    if (filteredFindings.length > 0) {
      if (!selectedFinding || !filteredFindings.some((f) => f.finding_id === selectedFinding.finding_id)) {
        setSelectedFinding(filteredFindings[0]);
      }
    } else {
      setSelectedFinding(null);
    }
  }, [filteredFindings]);

  const handleResetFilters = () => {
    setScannerFilter([]);
    setTierFilter([]);
    setHostFilter([]);
    setKevOnly(false);
    setMinScore(0);
  };

  const metrics = scanData.metrics || {};

  return (
    <div className="app-container">
      <Header
        scans={scans}
        selectedScanId={selectedScanId}
        onSelectScan={(id) => setSelectedScanId(id)}
        onRefresh={() => {
          fetchScans(true);
          loadScanDetails();
        }}
        loading={loadingScans || loadingScanData}
      />

      <div className="main-layout">
        <Sidebar
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
          scanId={selectedScanId}
        />

        <main className="content-area">
          {loadingScans && scans.length === 0 ? (
            <div className="state-loading">
              <div className="spinner" />
              <p>Connecting to Threat-X engine and scanning for runs...</p>
            </div>
          ) : error ? (
            <div className="state-error">
              <AlertCircle size={36} color="#ef4444" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: '700' }}>Unable to load scan data</h3>
              <p style={{ maxWidth: '460px', fontSize: '0.85rem' }}>{error}</p>
              <button className="btn btn-secondary" onClick={() => fetchScans(false)}>
                Retry Connection
              </button>
            </div>
          ) : scans.length === 0 ? (
            <div className="state-empty">
              <Layers size={40} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '1.2rem', fontWeight: '700' }}>No scored runs found yet</h3>
              <p style={{ maxWidth: '480px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                Run the Threat-X pipeline first from your terminal:
                <br />
                <code style={{ display: 'inline-block', marginTop: '10px', padding: '6px 12px', background: 'var(--bg-surface-elevated)', borderRadius: '6px', fontFamily: 'var(--font-mono)' }}>
                  python pipeline.py run --scan-id demo --use-fixtures
                </code>
              </p>
            </div>
          ) : (
            <>
              {/* Noise reduction funnel metrics */}
              <section className="metrics-section">
                <div className="section-header">
                  <h3 className="section-title">
                    <ShieldCheck size={20} color="var(--accent-cyan)" />
                    <span>Noise Reduction: Before vs. After</span>
                  </h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Scan ID: {selectedScanId}
                  </span>
                </div>

                <div className="metrics-grid">
                  <MetricCard
                    title="Raw Findings"
                    value={metrics.raw_count}
                    badgeText="Input findings"
                    badgeVariant="blue"
                  />
                  <MetricCard
                    title="Duplicates Removed"
                    value={metrics.duplicate_count}
                    badgeText={`-${metrics.dedup_pct ?? 0}%`}
                    badgeVariant="orange"
                  />
                  <MetricCard
                    title="Suppressed (FP / Accepted)"
                    value={metrics.suppressed_count}
                    badgeText={`-${metrics.fp_removed_pct ?? 0}%`}
                    badgeVariant="orange"
                  />
                  <MetricCard
                    title="Final Ranked Findings"
                    value={metrics.final_count}
                    badgeText={`-${metrics.noise_reduction_pct ?? 0}% total noise`}
                    badgeVariant="green"
                  />
                </div>
              </section>

              {/* Ranked findings table */}
              <FindingsTable
                findings={filteredFindings}
                selectedFindingId={selectedFinding?.finding_id}
                onSelectFinding={(f) => setSelectedFinding(f)}
                totalActionableCount={actionableFindings.length}
              />

              {/* Finding Detail Panel */}
              <FindingDetail
                finding={selectedFinding}
                allFilteredFindings={filteredFindings}
                onSelectFinding={(f) => setSelectedFinding(f)}
                scanId={selectedScanId}
                onTicketUpdated={loadScanDetails}
              />

              {/* Charts Grid */}
              <section className="charts-grid">
                <ScannerChart allFindings={findings} />
                <SlaChart actionableFindings={actionableFindings} />
                <ScannerOverlap actionableFindings={actionableFindings} />
              </section>
            </>
          )}
        </main>
      </div>
    </div>
  );
}

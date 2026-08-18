import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from './components/layout/Sidebar';
import Topbar from './components/layout/Topbar';
import DashboardPage from './pages/DashboardPage';
import FindingsPage from './pages/FindingsPage';
import ScansPage from './pages/ScansPage';
import TicketsPage from './pages/TicketsPage';
import { api } from './services/api';
import { ErrorState } from './components/common/EmptyState';
import { Loader2 } from 'lucide-react';

function parseUrlState() {
  try {
    const params = new URLSearchParams(window.location.search);
    const viewParam = params.get('view');
    const severityParam = params.get('severity') || params.get('tier') || params.get('sla');
    const kevParam = params.get('kev');
    const scopeParam = params.get('scope');
    const actionableParam = params.get('actionable');
    const scannerParam = params.get('scanner');
    const hostParam = params.get('host');
    const searchParam = params.get('search') || params.get('q');
    const minScoreParam = params.get('minScore');

    let initialView = viewParam || 'overview';
    if (!viewParam && (severityParam || kevParam || scopeParam || actionableParam || scannerParam || hostParam || searchParam)) {
      initialView = 'findings';
    }

    let initialFilter = null;
    if (initialView === 'findings') {
      initialFilter = {};
      if (scopeParam) initialFilter.scope = scopeParam;
      else if (actionableParam === 'true') initialFilter.scope = 'actionable';
      if (severityParam) initialFilter.tier = severityParam.toLowerCase();
      if (kevParam === 'true') initialFilter.kev = true;
      if (scannerParam) initialFilter.scanner = scannerParam;
      if (hostParam) initialFilter.host = hostParam;
      if (searchParam) initialFilter.search = searchParam;
      if (minScoreParam) initialFilter.minScore = Number(minScoreParam);
    }

    return { view: initialView, filter: initialFilter };
  } catch (e) {
    return { view: 'overview', filter: null };
  }
}

function updateBrowserUrl(view, filter = null) {
  try {
    const params = new URLSearchParams();
    if (view && view !== 'overview') {
      params.set('view', view);
    }
    if (view === 'findings' && filter) {
      if (filter.scope && filter.scope !== 'actionable') params.set('scope', filter.scope);
      if (filter.tier) params.set('severity', filter.tier);
      if (filter.kev) params.set('kev', 'true');
      if (filter.scanner) params.set('scanner', filter.scanner);
      if (filter.host) params.set('host', filter.host);
      if (filter.search) params.set('search', filter.search);
      if (filter.minScore) params.set('minScore', filter.minScore);
    }
    const newQuery = params.toString() ? `?${params.toString()}` : window.location.pathname;
    const currentUrl = window.location.pathname + window.location.search;
    if (newQuery !== currentUrl && (newQuery || currentUrl !== window.location.pathname)) {
      window.history.pushState({ view, filter }, '', newQuery || window.location.pathname);
    }
  } catch (e) {
    // Ignore history API limitations if any
  }
}

export default function App() {
  const initialUrlState = useMemo(() => parseUrlState(), []);

  // Navigation
  const [activeView, setActiveView] = useState(initialUrlState.view);
  const [findingsFilter, setFindingsFilter] = useState(initialUrlState.filter);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Scan & Findings Data
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [scanData, setScanData] = useState({ metrics: {} });
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Status
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingScanData, setLoadingScanData] = useState(false);
  const [error, setError] = useState(null);

  // Handle browser back / forward buttons
  useEffect(() => {
    const handlePopState = () => {
      const state = parseUrlState();
      setActiveView(state.view);
      setFindingsFilter(state.filter);
      setSelectedFinding(null);
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigateToView = (view, filter = null) => {
    setActiveView(view);
    setFindingsFilter(filter);
    setSelectedFinding(null);
    updateBrowserUrl(view, filter);
  };

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
      setError(err.message || 'Unable to connect to Threat-X backend API.');
    } finally {
      setLoadingScans(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    fetchScans(false);
  }, []);

  // Fetch scan detail & findings
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
    } catch (err) {
      setError(err.message || `Unable to load scan "${selectedScanId}".`);
    } finally {
      setLoadingScanData(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    loadScanDetails();
  }, [loadScanDetails]);

  // Derived counts
  const actionableFindings = useMemo(() => {
    return findings.filter((f) => !f.is_duplicate && !f.suppressed);
  }, [findings]);

  const ticketsCount = useMemo(() => {
    return findings.filter((f) => f.github_issue_number != null).length;
  }, [findings]);

  const handleKpiClick = (kpiType) => {
    let filterPayload = {};
    switch (kpiType) {
      case 'actionable':
        filterPayload = { scope: 'actionable' };
        break;
      case 'critical':
        filterPayload = { scope: 'actionable', tier: 'critical' };
        break;
      case 'high':
        filterPayload = { scope: 'actionable', tier: 'high' };
        break;
      case 'kev':
        filterPayload = { scope: 'actionable', kev: true };
        break;
      case 'dedup_fp':
        filterPayload = { scope: 'dedup_fp' };
        break;
      default:
        filterPayload = {};
    }
    navigateToView('findings', filterPayload);
  };

  return (
    <div className="app-shell">
      {/* Persistent Enterprise Sidebar */}
      <Sidebar
        activeView={activeView}
        onNavigate={(view) => {
          navigateToView(view, null);
        }}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        findingsCount={actionableFindings.length}
        ticketsCount={ticketsCount}
        scansCount={scans.length}
      />

      {/* Main Content Area */}
      <div className="app-main">
        {/* Enterprise Topbar */}
        <Topbar
          activeView={activeView}
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectScan={(id) => {
            setSelectedScanId(id);
            setSelectedFinding(null);
          }}
          onRefresh={() => {
            fetchScans(true);
            loadScanDetails();
          }}
          loading={loadingScans || loadingScanData}
        />

        {/* Dynamic Page Views */}
        {loadingScans && scans.length === 0 ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', gap: '10px' }}>
            <Loader2 size={24} className="spinner" />
            <span>Loading Threat-X operations console...</span>
          </div>
        ) : error ? (
          <div style={{ padding: '40px' }}>
            <ErrorState
              title="Connection Error"
              message={error}
              onRetry={() => {
                fetchScans(false);
                loadScanDetails();
              }}
            />
          </div>
        ) : (
          <>
            {activeView === 'overview' && (
              <DashboardPage
                scanId={selectedScanId}
                scanData={scanData}
                allFindings={findings}
                actionableFindings={actionableFindings}
                onNavigate={navigateToView}
                onKpiClick={handleKpiClick}
                selectedFinding={selectedFinding}
                onSelectFinding={setSelectedFinding}
                onCloseFinding={() => setSelectedFinding(null)}
                onTicketUpdated={loadScanDetails}
              />
            )}

            {activeView === 'findings' && (
              <FindingsPage
                scanId={selectedScanId}
                findings={findings}
                selectedFinding={selectedFinding}
                onSelectFinding={setSelectedFinding}
                onCloseFinding={() => setSelectedFinding(null)}
                onTicketUpdated={loadScanDetails}
                initialFilter={findingsFilter}
                onFilterChange={(newFilter) => {
                  setFindingsFilter((prev) => ({ ...(prev || {}), ...newFilter }));
                  updateBrowserUrl('findings', { ...(findingsFilter || {}), ...newFilter });
                }}
              />
            )}

            {activeView === 'scans' && (
              <ScansPage
                scans={scans}
                selectedScanId={selectedScanId}
                onSelectScan={setSelectedScanId}
                onNavigate={navigateToView}
                onScanCompleted={(newId) => {
                  fetchScans(false).then(() => {
                    setSelectedScanId(newId);
                    navigateToView('findings', null);
                  });
                }}
              />
            )}

            {activeView === 'tickets' && (
              <TicketsPage
                scanId={selectedScanId}
                findings={findings}
                selectedFinding={selectedFinding}
                onSelectFinding={setSelectedFinding}
                onCloseFinding={() => setSelectedFinding(null)}
                onTicketUpdated={loadScanDetails}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}

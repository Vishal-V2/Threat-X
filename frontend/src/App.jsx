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

export default function App() {
  // Navigation
  const [activeView, setActiveView] = useState('overview');
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

  return (
    <div className="app-shell">
      {/* Persistent Enterprise Sidebar */}
      <Sidebar
        activeView={activeView}
        onNavigate={(view) => {
          setActiveView(view);
          setSelectedFinding(null); // close drawer on nav
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
                onNavigate={setActiveView}
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
              />
            )}

            {activeView === 'scans' && (
              <ScansPage
                scans={scans}
                selectedScanId={selectedScanId}
                onSelectScan={setSelectedScanId}
                onNavigate={setActiveView}
                onScanCompleted={(newId) => {
                  fetchScans(false).then(() => {
                    setSelectedScanId(newId);
                    setActiveView('findings');
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

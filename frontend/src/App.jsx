import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Activity, 
  Layers, 
  Sparkles, 
  Play, 
  RefreshCw, 
  AlertCircle,
  CheckCircle2,
  Lock,
  Flame,
  GitPullRequest
} from 'lucide-react';

import Navbar from './components/Navbar';
import NoiseReductionFunnel from './components/NoiseReductionFunnel';
import ActionableFindingsTable from './components/ActionableFindingsTable';
import NoiseVaultView from './components/NoiseVaultView';
import FindingDetailModal from './components/FindingDetailModal';

import { fetchScans, fetchScanDetails, triggerScan } from './services/api';

export default function App() {
  const [scans, setScans] = useState([]);
  const [currentScanId, setCurrentScanId] = useState('demo');
  const [scanData, setScanData] = useState(null);
  const [activeTab, setActiveTab] = useState('actionable'); // 'actionable' | 'noise_reduction'
  
  const [isLoading, setIsLoading] = useState(true);
  const [isTriggering, setIsTriggering] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const [selectedFinding, setSelectedFinding] = useState(null);

  // Load initial scans
  useEffect(() => {
    loadScansList();
  }, []);

  const loadScansList = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const scansList = await fetchScans();
      setScans(scansList);
      if (scansList.length > 0) {
        const defaultId = scansList[0].scan_id;
        setCurrentScanId(defaultId);
        await loadScanData(defaultId);
      } else {
        // Fallback to demo scan
        await loadScanData('demo');
      }
    } catch (err) {
      console.error('Failed to load scans:', err);
      setErrorMsg(`Could not connect to Threat-X API bridge: ${err.message}. Ensure api.py is running on port 8000.`);
    } finally {
      setIsLoading(false);
    }
  };

  const loadScanData = async (scanId) => {
    setErrorMsg(null);
    try {
      const data = await fetchScanDetails(scanId);
      setScanData(data);
    } catch (err) {
      console.error(`Failed to load scan data for ${scanId}:`, err);
      setErrorMsg(`Failed to load findings for scan "${scanId}": ${err.message}`);
    }
  };

  const handleSelectScan = (scanId) => {
    setCurrentScanId(scanId);
    loadScanData(scanId);
  };

  const handleTriggerPipeline = async () => {
    setIsTriggering(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const res = await triggerScan(currentScanId, true);
      setSuccessMsg(`Pipeline re-executed successfully for "${currentScanId}"!`);
      await loadScanData(currentScanId);
      const updatedScans = await fetchScans();
      setScans(updatedScans);
    } catch (err) {
      setErrorMsg(`Pipeline run failed: ${err.message}`);
    } finally {
      setIsTriggering(false);
      setTimeout(() => setSuccessMsg(null), 5000);
    }
  };

  return (
    <div className="min-h-screen bg-[#080c16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <Navbar
        scans={scans}
        currentScanId={currentScanId}
        onSelectScan={handleSelectScan}
        onTriggerScan={handleTriggerPipeline}
        isTriggering={isTriggering}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        metrics={scanData?.metrics}
      />

      {/* Notification Toasts */}
      {errorMsg && (
        <div className="max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 mt-4">
          <div className="p-3.5 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-200 text-xs flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-rose-400 hover:text-rose-200 font-bold px-2 py-0.5"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {successMsg && (
        <div className="max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 mt-4">
          <div className="p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-200 text-xs flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
            <button
              onClick={() => setSuccessMsg(null)}
              className="text-emerald-400 hover:text-emerald-200 font-bold px-2 py-0.5"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Top Noise Reduction Funnel */}
        <NoiseReductionFunnel
          metrics={scanData?.metrics}
          scannerBreakdown={scanData?.scanner_breakdown}
        />

        {/* Tab 1: Actionable Ranked Findings */}
        {activeTab === 'actionable' && (
          <div className="space-y-4">
            <ActionableFindingsTable
              findings={scanData?.actionable_findings || []}
              onSelectFinding={(f) => setSelectedFinding(f)}
            />
          </div>
        )}

        {/* Tab 2: Noise Reduction Audit Vault */}
        {activeTab === 'noise_reduction' && (
          <div className="space-y-4">
            <NoiseVaultView
              duplicateFindings={scanData?.duplicate_findings || []}
              suppressedFindings={scanData?.suppressed_findings || []}
            />
          </div>
        )}
      </main>

      {/* Finding Detail & Score Breakdown Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        isOpen={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 bg-[#060912] text-center text-xs text-slate-500 font-mono">
        Threat-X
      </footer>
    </div>
  );
}

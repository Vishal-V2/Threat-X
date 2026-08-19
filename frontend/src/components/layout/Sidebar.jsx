import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Radar,
  Ticket,
  Shield,
  ChevronLeft,
  ChevronRight,
  Terminal,
} from 'lucide-react';

export default function Sidebar({
  activeView,
  onNavigate,
  collapsed,
  onToggleCollapse,
  findingsCount = 0,
  ticketsCount = 0,
  scansCount = 0,
}) {
  return (
    <aside className={`app-sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-brand">
        <a href="#overview" className="brand-identity" onClick={(e) => { e.preventDefault(); onNavigate('overview'); }}>
          <div className="brand-icon">
            <Shield size={16} strokeWidth={2.5} />
          </div>
          {!collapsed && <span>THREAT-X</span>}
        </a>
        <button
          onClick={onToggleCollapse}
          style={{ background: 'transparent', border: 'none', color: 'var(--text-sidebar-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      <nav className="sidebar-nav">
        {/* Main Section */}
        <div className="nav-section">
          <button
            className={`nav-item ${activeView === 'overview' ? 'active' : ''}`}
            onClick={() => onNavigate('overview')}
            title="Overview"
          >
            <LayoutDashboard size={16} />
            {!collapsed && <span>Overview</span>}
          </button>
        </div>

        {/* Operations Section */}
        <div className="nav-section">
          {!collapsed && <div className="nav-section-title">Operations</div>}
          <button
            className={`nav-item ${activeView === 'findings' ? 'active' : ''}`}
            onClick={() => onNavigate('findings')}
            title="Findings"
          >
            <ShieldAlert size={16} />
            {!collapsed && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <span>Findings</span>
                {findingsCount > 0 && (
                  <span style={{ fontSize: '10px', background: '#1e293b', padding: '1px 6px', borderRadius: '10px', color: 'var(--text-sidebar)' }}>
                    {findingsCount}
                  </span>
                )}
              </div>
            )}
          </button>

          <button
            className={`nav-item ${activeView === 'scans' ? 'active' : ''}`}
            onClick={() => onNavigate('scans')}
            title="Scans"
          >
            <Radar size={16} />
            {!collapsed && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <span>Scans</span>
                {scansCount > 0 && (
                  <span style={{ fontSize: '10px', background: '#1e293b', padding: '1px 6px', borderRadius: '10px', color: 'var(--text-sidebar)' }}>
                    {scansCount}
                  </span>
                )}
              </div>
            )}
          </button>
        </div>

        {/* Workflow Section */}
        <div className="nav-section">
          {!collapsed && <div className="nav-section-title">Workflow</div>}
          <button
            className={`nav-item ${activeView === 'tickets' ? 'active' : ''}`}
            onClick={() => onNavigate('tickets')}
            title="Tickets"
          >
            <Ticket size={16} />
            {!collapsed && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <span>Tickets</span>
                {ticketsCount > 0 && (
                  <span style={{ fontSize: '10px', background: '#1e293b', padding: '1px 6px', borderRadius: '10px', color: 'var(--text-sidebar)' }}>
                    {ticketsCount}
                  </span>
                )}
              </div>
            )}
          </button>
        </div>
      </nav>

      {!collapsed && (
        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Terminal size={13} />
            <span>Threat-X Core v1.0</span>
          </div>
          <span style={{ color: '#22c55e', fontSize: '10px', fontWeight: 600 }}>CONNECTED</span>
        </div>
      )}
    </aside>
  );
}

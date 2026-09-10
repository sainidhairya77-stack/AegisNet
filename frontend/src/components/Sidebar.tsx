import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  FileSearch, 
  AlertTriangle, 
  Network, 
  ShieldAlert,
  Terminal,
  Activity
} from 'lucide-react';

const navItems = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/analyzer', label: 'PCAP Traffic Analyzer', icon: FileSearch },
  { path: '/incidents', label: 'Incidents & Alerts', icon: AlertTriangle },
  { path: '/topology', label: 'Network Attack Graph', icon: Network },
  { path: '/simulation', label: 'Defense Simulation', icon: ShieldAlert },
];

export const Sidebar: React.FC = () => {
  return (
    <aside style={{
      width: '260px',
      background: '#070b14',
      borderRight: '1px solid var(--border-color)',
      display: 'flex',
      flexDirection: 'column',
      padding: '1.5rem 1rem',
      gap: '0.5rem',
      flexShrink: 0
    }}>
      <div style={{
        fontSize: '0.7rem',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        color: 'var(--text-dim)',
        padding: '0 0.75rem',
        marginBottom: '0.5rem',
        fontWeight: 700
      }}>
        Operations Center
      </div>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.75rem 0.85rem',
                borderRadius: 'var(--radius-sm)',
                color: isActive ? 'var(--primary)' : 'var(--text-muted)',
                background: isActive ? 'rgba(6, 182, 212, 0.08)' : 'transparent',
                border: isActive ? '1px solid rgba(6, 182, 212, 0.25)' : '1px solid transparent',
                textDecoration: 'none',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.875rem',
                transition: 'all 0.15s ease'
              })}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: '1.5rem', borderTop: '1px solid var(--border-color)' }}>
        <div style={{
          background: '#0a101f',
          padding: '1rem',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-color)',
          fontSize: '0.75rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--primary)', fontWeight: 600, marginBottom: '0.4rem' }}>
            <Activity size={14} />
            <span>Detection Pipelines</span>
          </div>
          <div style={{ color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Rule Engine:</span> <span style={{ color: 'var(--success)' }}>Active (4 Rules)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>ML Isolation Forest:</span> <span style={{ color: 'var(--primary)' }}>Trained</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Firewall Mode:</span> <span style={{ color: 'var(--warning)' }}>Mock / Safe</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};

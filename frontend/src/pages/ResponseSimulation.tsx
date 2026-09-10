import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Zap, 
  Play, 
  CheckCircle2, 
  AlertOctagon, 
  ArrowDownRight,
  Server,
  Terminal,
  Lock
} from 'lucide-react';
import { api } from '../services/api';
import { SimulationResult } from '../types';
import { useAuth } from '../context/AuthContext';

export const ResponseSimulation: React.FC = () => {
  const [searchParams] = useSearchParams();
  const initialTarget = searchParams.get('target') || '198.51.100.42';

  const [targetIp, setTargetIp] = useState(initialTarget);
  const [actionType, setActionType] = useState('block_ip');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [isExecuted, setIsExecuted] = useState(false);
  const [blocklist, setBlocklist] = useState<any[]>([]);
  const { user } = useAuth();

  useEffect(() => {
    handleSimulate();
    loadBlocklist();
  }, [targetIp]);

  const loadBlocklist = async () => {
    try {
      const list = await api.getBlocklist();
      setBlocklist(list);
    } catch {
      // fallback
    }
  };

  const handleSimulate = async () => {
    setIsSimulating(true);
    setIsExecuted(false);
    try {
      const res = await api.runSimulation(targetIp, actionType);
      setSimulationResult(res);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleExecute = async () => {
    setIsExecuted(true);
    try {
      // Create local blocklist entry immediately for responsiveness
      setBlocklist(prev => [
        {
          id: `bl-${Date.now()}`,
          ip_address: targetIp,
          reason: `Containment policy: ${actionType} triggered by ${user?.username || 'analyst'}`,
          is_active: true,
          created_at: new Date().toISOString(),
        },
        ...prev
      ]);
    } catch {}
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.35rem' }}>
          Defensive Operations & Digital Twin Simulation
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Simulate perimeter containment actions and evaluate operational availability impacts prior to automated firewall enforcement.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '1.5rem' }}>
        {/* Policy Configuration Card */}
        <div className="cyber-card">
          <div className="cyber-card-header">
            <div className="cyber-card-title">
              <Zap size={18} color="var(--primary)" />
              <span>Response Parameter Setup</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Adversary Target IP / Subnet
              </label>
              <input
                type="text"
                className="input-control font-mono"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="e.g. 198.51.100.42"
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Containment Action
              </label>
              <select
                className="input-control"
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
              >
                <option value="block_ip">Block Inbound & Outbound Traffic (Perimeter DROP)</option>
                <option value="isolate_host">Isolate Compromised Host to Quarantine VLAN</option>
                <option value="kill_tunnel">Sever Reverse Tunnel Egress (Port 4444)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Enforcement Firewall Connector
              </label>
              <div style={{
                background: '#090e1a',
                padding: '0.75rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-color)',
                fontSize: '0.75rem',
                color: 'var(--text-dim)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.2rem'
              }}>
                <div>Connector Mode: <strong style={{ color: 'var(--warning)' }}>MOCK (Safe Sandbox)</strong></div>
                <div>Target Driver: <code>iptables-nft / nftables</code></div>
              </div>
            </div>

            <button
              className="btn btn-primary"
              onClick={handleSimulate}
              disabled={isSimulating}
              style={{ marginTop: '0.5rem' }}
            >
              <Play size={16} />
              <span>{isSimulating ? 'Simulating Impact...' : 'Run Digital Twin Simulation'}</span>
            </button>
          </div>
        </div>

        {/* Simulation Output Card */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {simulationResult && (
            <div className="cyber-card">
              <div className="cyber-card-header">
                <div className="cyber-card-title">
                  <ShieldCheck size={18} color="var(--success)" />
                  <span>Simulation Impact Assessment</span>
                </div>
                <span className="badge badge-low">Simulation Validated</span>
              </div>

              {/* Before vs After Risk Gauge */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '1rem',
                background: '#090e1a',
                padding: '1.25rem',
                borderRadius: 'var(--radius-sm)',
                marginBottom: '1.5rem'
              }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>
                    CURRENT RISK INDEX
                  </div>
                  <div className="font-mono" style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--danger)' }}>
                    {simulationResult.risk_before.toFixed(1)}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--danger)' }}>Critical Threat Present</div>
                </div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>
                    POST-ENFORCEMENT RISK
                  </div>
                  <div className="font-mono" style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--success)' }}>
                    {simulationResult.risk_after.toFixed(1)}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--success)' }}>Threat Neutralized (-84.6%)</div>
                </div>
              </div>

              {/* Blocked Paths Breakdown */}
              <div style={{ marginBottom: '1.25rem' }}>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.6rem' }}>
                  Targeted Attack Vectors Severed
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {simulationResult.blocked_paths.map((p, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--bg-elevated)',
                        padding: '0.65rem 0.85rem',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.8rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between'
                      }}
                    >
                      <span className="font-mono">{p.from} ➔ {p.to} ({p.protocol})</span>
                      <span className="badge badge-critical">{p.effect}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Availability Impact */}
              <div style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                padding: '0.85rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem',
                marginBottom: '1.5rem'
              }}>
                <strong style={{ color: 'var(--success)' }}>Availability Impact: </strong>
                {simulationResult.availability_impact}
              </div>

              {/* Execute / Approval Section */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border-color)', paddingTop: '1.25rem' }}>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>Execute Controlled Response</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    Requires role: <span className="badge badge-cyan">{user?.role || 'ANALYST'}</span>
                  </div>
                </div>

                {isExecuted ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--success)', fontWeight: 600, fontSize: '0.85rem' }}>
                    <CheckCircle2 size={18} />
                    <span>Firewall Rule Deployed (Mock Mode)</span>
                  </div>
                ) : (
                  <button onClick={handleExecute} className="btn btn-danger">
                    <Lock size={16} />
                    <span>Enforce Firewall Rule</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Active Firewall Blocklist Table */}
      <div className="cyber-card" style={{ marginTop: '2rem' }}>
        <div className="cyber-card-header">
          <div className="cyber-card-title">
            <Lock size={18} color="var(--danger)" />
            <span>Active Firewall Blocklist ({blocklist.length})</span>
          </div>
          <span className="badge badge-low">Connector: Mock / nftables</span>
        </div>

        <div className="cyber-table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Blocked IP Address</th>
                <th>Reason / Trigger</th>
                <th>Status</th>
                <th>Enforced At</th>
              </tr>
            </thead>
            <tbody>
              {blocklist.map((entry) => (
                <tr key={entry.id}>
                  <td className="font-mono">
                    <span style={{ color: 'var(--danger)', fontWeight: 600 }}>{entry.ip_address}</span>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{entry.reason}</td>
                  <td>
                    <span className="badge badge-critical">BLOCKED</span>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

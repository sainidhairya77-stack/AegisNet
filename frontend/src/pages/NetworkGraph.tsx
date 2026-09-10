import React, { useState, useEffect } from 'react';
import { 
  Network, 
  ShieldAlert, 
  Server, 
  Database, 
  Globe, 
  Radio, 
  ArrowRight,
  Shield,
  Layers,
  Info
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { NetworkGraph as NetworkGraphType, GraphNode } from '../types';

export const NetworkGraph: React.FC = () => {
  const [graphData, setGraphData] = useState<NetworkGraphType | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    loadGraph();
  }, []);

  const loadGraph = async () => {
    const res = await api.getGraph('default');
    setGraphData(res);
    if (res.nodes.length > 0) {
      setSelectedNode(res.nodes[0]);
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'external': return <Globe size={20} color="var(--danger)" />;
      case 'server': return <Server size={20} color="var(--warning)" />;
      case 'database': return <Database size={20} color="var(--danger)" />;
      default: return <Radio size={20} color="var(--primary)" />;
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.35rem' }}>
          Network Topology & Attack Path Graph
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Interactive visualization of observed communications, lateral movement hops, and high-risk exfiltration channels.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '1.5rem' }}>
        {/* Interactive Visual Graph Canvas */}
        <div className="cyber-card" style={{ padding: '1.5rem', minHeight: '520px', display: 'flex', flexDirection: 'column' }}>
          <div className="cyber-card-header">
            <div className="cyber-card-title">
              <Network size={18} color="var(--primary)" />
              <span>Observed Communication Topology</span>
            </div>
            <span className="badge badge-critical">Attack Vector Mapped</span>
          </div>

          {/* SVG Map Canvas */}
          <div style={{
            flex: 1,
            background: 'radial-gradient(circle at 50% 50%, #0a1122 0%, #050811 100%)',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-sm)',
            position: 'relative',
            overflow: 'hidden',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '400px'
          }}>
            {/* SVG Attack Lines */}
            <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
              <defs>
                <linearGradient id="attackGlow" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
                </linearGradient>
              </defs>

              {/* Attacker -> Web Server */}
              <line x1="18%" y1="35%" x2="48%" y2="35%" stroke="url(#attackGlow)" strokeWidth="3" strokeDasharray="6" />
              {/* Web Server -> DB Server */}
              <line x1="52%" y1="40%" x2="78%" y2="65%" stroke="url(#attackGlow)" strokeWidth="3" strokeDasharray="6" />
              {/* DB Server -> Attacker (Exfiltration) */}
              <path d="M 80% 60% Q 50% 85% 20% 40%" fill="none" stroke="#ef4444" strokeWidth="3" strokeDasharray="4" />
              {/* Scanner -> Gateway */}
              <line x1="20%" y1="75%" x2="50%" y2="75%" stroke="#3b82f6" strokeWidth="2" strokeDasharray="2" />
            </svg>

            {/* Nodes Representation */}
            {/* Node 1: External Attacker */}
            <div
              onClick={() => setSelectedNode(graphData?.nodes[0] || null)}
              style={{
                position: 'absolute',
                left: '12%',
                top: '30%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'node-ext-1' ? 'scale(1.08)' : 'scale(1)',
                transition: 'all 0.2s',
              }}
            >
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '2px solid #ef4444',
                boxShadow: '0 0 20px rgba(239, 68, 68, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.4rem',
              }}>
                <Globe size={24} color="#ef4444" />
              </div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#f87171' }}>Threat Actor</div>
              <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>198.51.100.42</div>
            </div>

            {/* Node 2: Web Server (DMZ) */}
            <div
              onClick={() => setSelectedNode(graphData?.nodes[1] || null)}
              style={{
                position: 'absolute',
                left: '48%',
                top: '30%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'node-web-1' ? 'scale(1.08)' : 'scale(1)',
                transition: 'all 0.2s',
              }}
            >
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                background: 'rgba(245, 158, 11, 0.15)',
                border: '2px solid #f59e0b',
                boxShadow: '0 0 20px rgba(245, 158, 11, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.4rem',
              }}>
                <Server size={24} color="#f59e0b" />
              </div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>DMZ Web Server</div>
              <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>10.0.0.15</div>
            </div>

            {/* Node 3: Database (Target) */}
            <div
              onClick={() => setSelectedNode(graphData?.nodes[2] || null)}
              style={{
                position: 'absolute',
                left: '78%',
                top: '58%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'node-db-1' ? 'scale(1.08)' : 'scale(1)',
                transition: 'all 0.2s',
              }}
            >
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                background: 'rgba(239, 68, 68, 0.2)',
                border: '2px solid #ef4444',
                boxShadow: '0 0 25px rgba(239, 68, 68, 0.5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.4rem',
              }}>
                <Database size={24} color="#ef4444" />
              </div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#f87171' }}>Critical Database</div>
              <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>10.0.0.99</div>
            </div>

            {/* Node 4: Scanner Host */}
            <div
              onClick={() => setSelectedNode(graphData?.nodes[4] || null)}
              style={{
                position: 'absolute',
                left: '14%',
                top: '70%',
                cursor: 'pointer',
                textAlign: 'center',
              }}
            >
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '50%',
                background: 'rgba(59, 130, 246, 0.15)',
                border: '2px solid #3b82f6',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.4rem',
              }}>
                <Globe size={18} color="#3b82f6" />
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Scanner Host</div>
              <div className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-dim)' }}>203.0.113.88</div>
            </div>

            {/* Node 5: App Gateway */}
            <div
              onClick={() => setSelectedNode(graphData?.nodes[3] || null)}
              style={{
                position: 'absolute',
                left: '48%',
                top: '70%',
                cursor: 'pointer',
                textAlign: 'center',
              }}
            >
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '50%',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '2px solid #10b981',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.4rem',
              }}>
                <Radio size={18} color="#10b981" />
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>App Gateway</div>
              <div className="font-mono" style={{ fontSize: '0.65rem', color: 'var(--text-dim)' }}>10.0.0.22</div>
            </div>
          </div>
        </div>

        {/* Node Inspector & Attack Path Sequence */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {selectedNode && (
            <div className="cyber-card">
              <div className="cyber-card-header">
                <div className="cyber-card-title">
                  {getNodeIcon(selectedNode.type)}
                  <span>Node Telemetry: {selectedNode.ip}</span>
                </div>
                <span className={`badge ${selectedNode.risk_level === 'CRITICAL' ? 'badge-critical' : selectedNode.risk_level === 'HIGH' ? 'badge-high' : 'badge-low'}`}>
                  {selectedNode.risk_level} RISK
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
                <div>
                  <span style={{ color: 'var(--text-dim)' }}>Classification: </span>
                  <strong style={{ textTransform: 'uppercase' }}>{selectedNode.type}</strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-dim)' }}>Asset Label: </span>
                  <span>{selectedNode.label}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-dim)' }}>Observed Role: </span>
                  <span style={{ color: selectedNode.type === 'external' ? 'var(--danger)' : 'var(--text-main)' }}>
                    {selectedNode.type === 'external' ? 'Command & Control Endpoint' : 'Internal Infrastructure'}
                  </span>
                </div>
              </div>

              {selectedNode.type === 'external' && (
                <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
                  <Link to={`/simulation?target=${selectedNode.ip}`} className="btn btn-danger btn-sm" style={{ width: '100%' }}>
                    <Shield size={14} />
                    Simulate Firewall Containment
                  </Link>
                </div>
              )}
            </div>
          )}

          {/* Attack Path Analysis Card */}
          <div className="cyber-card">
            <div className="cyber-card-header">
              <div className="cyber-card-title">
                <ShieldAlert size={18} color="var(--danger)" />
                <span>Reconstructed Attack Path</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span className="badge badge-critical">Hop 1</span>
                <span className="font-mono">198.51.100.42</span>
                <ArrowRight size={12} color="var(--danger)" />
                <span className="font-mono">10.0.0.15:443</span>
              </div>
              <div style={{ color: 'var(--text-muted)', paddingLeft: '2.5rem', fontSize: '0.75rem' }}>
                Initial ingress probe & web application compromise.
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span className="badge badge-high">Hop 2</span>
                <span className="font-mono">10.0.0.15</span>
                <ArrowRight size={12} color="var(--warning)" />
                <span className="font-mono">10.0.0.99:5432</span>
              </div>
              <div style={{ color: 'var(--text-muted)', paddingLeft: '2.5rem', fontSize: '0.75rem' }}>
                Lateral database privilege escalation using harvested credentials.
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span className="badge badge-critical">Hop 3</span>
                <span className="font-mono">10.0.0.99</span>
                <ArrowRight size={12} color="var(--danger)" />
                <span className="font-mono">198.51.100.42:4444</span>
              </div>
              <div style={{ color: 'var(--danger)', paddingLeft: '2.5rem', fontSize: '0.75rem', fontWeight: 600 }}>
                High-volume reverse tunnel exfiltrating database dumps.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

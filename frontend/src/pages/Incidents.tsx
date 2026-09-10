import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  Search, 
  ExternalLink, 
  ChevronRight, 
  Crosshair, 
  Clock, 
  CheckCircle,
  FileSearch,
  Shield
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { Incident, Alert, AlertSeverity } from '../types';
import { AIInvestigatorModal } from '../components/AIInvestigatorModal';
import { Bot, Sparkles } from 'lucide-react';

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [investigatingIncident, setInvestigatingIncident] = useState<Incident | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    const [incRes, alertRes] = await Promise.all([
      api.getIncidents(),
      api.getAlerts(),
    ]);
    setIncidents(incRes.incidents);
    setAlerts(alertRes.alerts);
    if (incRes.incidents.length > 0) {
      setSelectedIncident(incRes.incidents[0]);
    }
  };

  const filteredIncidents = incidents.filter(inc => {
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
    return true;
  });

  const getSeverityBadge = (severity: AlertSeverity) => {
    switch (severity) {
      case 'CRITICAL': return <span className="badge badge-critical">Critical</span>;
      case 'HIGH': return <span className="badge badge-high">High</span>;
      case 'MEDIUM': return <span className="badge badge-medium">Medium</span>;
      default: return <span className="badge badge-low">Low</span>;
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.35rem' }}>
          Correlated Security Incidents & Threat Alerts
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Adversary campaigns clustered using temporal correlation, shared IP patterns, and multi-factor risk scores.
        </p>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            className={`btn btn-sm ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setSeverityFilter(sev)}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Incident Grid & Inspection Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedIncident ? '1.1fr 1fr' : '1fr', gap: '1.5rem' }}>
        {/* Incident List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {filteredIncidents.map((incident) => {
            const isSelected = selectedIncident?.id === incident.id;
            return (
              <div 
                key={incident.id} 
                className="cyber-card"
                style={{ 
                  cursor: 'pointer',
                  borderColor: isSelected ? 'var(--primary)' : undefined,
                  background: isSelected ? 'rgba(6, 182, 212, 0.04)' : undefined,
                }}
                onClick={() => setSelectedIncident(incident)}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', marginBottom: '0.75rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                      {getSeverityBadge(incident.severity)}
                      <span className="badge badge-cyan">{incident.status}</span>
                    </div>
                    <div style={{ fontWeight: 700, fontSize: '1.05rem', color: 'var(--text-main)' }}>
                      {incident.title}
                    </div>
                  </div>

                  {/* Risk Score Circle / Meter */}
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div className="font-mono" style={{ 
                      fontSize: '1.5rem', 
                      fontWeight: 700, 
                      color: incident.risk_score >= 80 ? 'var(--danger)' : 'var(--warning)' 
                    }}>
                      {incident.risk_score.toFixed(1)}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>RISK INDEX</div>
                  </div>
                </div>

                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '1rem' }}>
                  {incident.description}
                </p>

                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  borderTop: '1px solid var(--border-color)',
                  paddingTop: '0.75rem',
                  fontSize: '0.8rem',
                  color: 'var(--text-dim)'
                }}>
                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <span>Attacker IPs: <strong style={{ color: 'var(--danger)' }}>{incident.source_ips?.join(', ') || 'N/A'}</strong></span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--primary)' }}>
                    <span>View Evidence</span>
                    <ChevronRight size={14} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Incident Drawer / Evidence View */}
        {selectedIncident && (
          <div className="cyber-card" style={{ position: 'sticky', top: '80px', height: 'fit-content' }}>
            <div className="cyber-card-header">
              <div className="cyber-card-title">
                <ShieldAlert size={18} color="var(--primary)" />
                <span>Incident Forensic Evidence</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button 
                  onClick={() => setInvestigatingIncident(selectedIncident)}
                  className="btn btn-primary btn-sm"
                >
                  <Bot size={14} />
                  <span>Ask AI Copilot</span>
                </button>
                <Link 
                  to={`/simulation?target=${selectedIncident.source_ips?.[0] || ''}`}
                  className="btn btn-danger btn-sm"
                >
                  <Shield size={14} />
                  Simulate
                </Link>
              </div>
            </div>

            <div style={{ marginBottom: '1.25rem', paddingBottom: '1rem', borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>CAMPAIGN TARGETS</div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {selectedIncident.destination_ips?.map((ip, i) => (
                  <span key={i} className="badge badge-cyan font-mono">{ip}</span>
                ))}
              </div>
            </div>

            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Correlated Detection Alerts ({alerts.length})
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '500px', overflowY: 'auto' }}>
              {alerts.map((alert) => (
                <div 
                  key={alert.id}
                  style={{
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.85rem'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      {getSeverityBadge(alert.severity)}
                      <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--primary)' }}>
                        {alert.rule_id}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      Confidence: {(alert.confidence * 100).toFixed(0)}%
                    </span>
                  </div>

                  <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.3rem' }}>
                    {alert.rule_name}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                    {alert.description}
                  </div>

                  {alert.evidence && (
                    <div style={{
                      background: '#090e1a',
                      padding: '0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-muted)'
                    }}>
                      <div style={{ color: 'var(--text-dim)', marginBottom: '0.2rem' }}>EVIDENCE PAYLOAD:</div>
                      {JSON.stringify(alert.evidence, null, 2)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {investigatingIncident && (
        <AIInvestigatorModal
          incident={investigatingIncident}
          pcapId={investigatingIncident.source_ips?.[0] || 'default'}
          onClose={() => setInvestigatingIncident(null)}
        />
      )}
    </div>
  );
};

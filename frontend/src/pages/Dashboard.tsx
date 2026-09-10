import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, 
  FileText, 
  Activity, 
  Zap, 
  UploadCloud, 
  ArrowRight,
  TrendingUp,
  AlertOctagon,
  CheckCircle2
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell
} from 'recharts';
import { api } from '../services/api';
import { PcapFile, Alert, Incident } from '../types';

const trafficData = [
  { time: '14:00', packets: 4200, threats: 2 },
  { time: '14:15', packets: 6800, threats: 1 },
  { time: '14:30', packets: 12400, threats: 8 },
  { time: '14:45', packets: 21900, threats: 24 },
  { time: '15:00', packets: 18500, threats: 19 },
  { time: '15:15', packets: 9800, threats: 6 },
  { time: '15:30', packets: 5100, threats: 1 },
];

const protocolData = [
  { name: 'TCP/443 (HTTPS)', flows: 1420, color: '#06b6d4' },
  { name: 'TCP/5432 (Postgres)', flows: 3290, color: '#ef4444' },
  { name: 'TCP/80 (HTTP)', flows: 812, color: '#3b82f6' },
  { name: 'TCP/22 (SSH)', flows: 320, color: '#f59e0b' },
  { name: 'UDP/53 (DNS)', flows: 540, color: '#10b981' },
];

export const Dashboard: React.FC = () => {
  const [pcaps, setPcaps] = useState<PcapFile[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        const [pcapRes, alertRes, incRes] = await Promise.all([
          api.listPcaps(),
          api.getAlerts(),
          api.getIncidents(),
        ]);
        setPcaps(pcapRes.pcaps);
        setAlerts(alertRes.alerts);
        setIncidents(incRes.incidents);
      } finally {
        setLoading(false);
      }
    };
    loadDashboardData();
  }, []);

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const maxRisk = incidents.reduce((max, inc) => Math.max(max, inc.risk_score), 0);

  return (
    <div>
      {/* Top Banner */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.35rem' }}>
          Network Defense Intelligence Center
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Real-time packet telemetry, behavioral anomaly detection, and automated threat correlation.
        </p>
      </div>

      {/* Key Metrics Grid */}
      <div className="grid-stats">
        <div className="cyber-card">
          <div className="cyber-card-header">
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
              Threat Risk Index
            </span>
            <AlertOctagon size={18} color="var(--danger)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.6rem' }}>
            <span style={{ fontSize: '2.2rem', fontWeight: 700, color: maxRisk > 80 ? 'var(--danger)' : 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
              {maxRisk.toFixed(1)}
            </span>
            <span style={{ color: 'var(--text-dim)', fontSize: '0.9rem' }}>/ 100</span>
          </div>
          <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--danger)' }}>
            <TrendingUp size={14} />
            <span>High priority threats requiring investigation</span>
          </div>
        </div>

        <div className="cyber-card">
          <div className="cyber-card-header">
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
              Active Incidents
            </span>
            <ShieldAlert size={18} color="var(--primary)" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            {incidents.length}
          </div>
          <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Correlated across <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{alerts.length} detections</span>
          </div>
        </div>

        <div className="cyber-card">
          <div className="cyber-card-header">
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
              Critical / High Alerts
            </span>
            <Zap size={18} color="var(--warning)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '2.2rem', fontWeight: 700, color: 'var(--danger)', fontFamily: 'var(--font-mono)' }}>
              {criticalCount}
            </span>
            <span style={{ color: 'var(--text-dim)', fontSize: '1.2rem' }}>+</span>
            <span style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--warning)', fontFamily: 'var(--font-mono)' }}>
              {highCount}
            </span>
          </div>
          <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Isolation Forest + Signature Rule Matches
          </div>
        </div>

        <div className="cyber-card">
          <div className="cyber-card-header">
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontWeight: 600, textTransform: 'uppercase' }}>
              PCAP Captures
            </span>
            <FileText size={18} color="var(--success)" />
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            {pcaps.length}
          </div>
          <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: 'var(--success)' }}>
            <CheckCircle2 size={14} />
            <span>Ready for full forensic replay</span>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid-cols-2" style={{ marginBottom: '2rem' }}>
        {/* Traffic & Threat Volume */}
        <div className="cyber-card">
          <div className="cyber-card-header">
            <div className="cyber-card-title">
              <Activity size={18} color="var(--primary)" />
              <span>Packet Volume & Threat Correlation</span>
            </div>
            <span className="badge badge-cyan">Live Telemetry</span>
          </div>
          <div style={{ height: '260px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficData}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={12} />
                <YAxis stroke="#475569" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#090e1a', borderColor: '#1e2d4d', borderRadius: '8px' }} 
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Area type="monotone" dataKey="packets" stroke="#06b6d4" fillOpacity={1} fill="url(#colorPackets)" name="Packets/s" />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" name="Threat Events" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="cyber-card">
          <div className="cyber-card-header">
            <div className="cyber-card-title">
              <Zap size={18} color="var(--warning)" />
              <span>Network Protocol Flow Distribution</span>
            </div>
          </div>
          <div style={{ height: '260px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolData} layout="vertical">
                <XAxis type="number" stroke="#475569" fontSize={12} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={130} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#090e1a', borderColor: '#1e2d4d', borderRadius: '8px' }} 
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Bar dataKey="flows" radius={[0, 4, 4, 0]}>
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent PCAP Captures & Quick Upload */}
      <div className="cyber-card">
        <div className="cyber-card-header">
          <div className="cyber-card-title">
            <FileText size={18} color="var(--primary)" />
            <span>Active Network PCAP Files</span>
          </div>
          <Link to="/analyzer" className="btn btn-primary btn-sm">
            <UploadCloud size={14} />
            Analyze New Capture
          </Link>
        </div>

        <div className="cyber-table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Capture Filename</th>
                <th>File Size</th>
                <th>SHA-256 Hash</th>
                <th>Status</th>
                <th>Uploaded At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {pcaps.map((pcap) => (
                <tr key={pcap.id}>
                  <td style={{ fontWeight: 600 }}>{pcap.original_filename}</td>
                  <td className="font-mono">{(pcap.file_size / (1024 * 1024)).toFixed(2)} MB</td>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {pcap.sha256_hash.slice(0, 16)}...
                  </td>
                  <td>
                    <span className={`badge ${pcap.status === 'COMPLETED' ? 'badge-low' : 'badge-cyan'}`}>
                      {pcap.status}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {new Date(pcap.uploaded_at).toLocaleDateString()} {new Date(pcap.uploaded_at).toLocaleTimeString()}
                  </td>
                  <td>
                    <Link to="/analyzer" className="btn btn-secondary btn-sm">
                      Inspect Flows <ArrowRight size={12} />
                    </Link>
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

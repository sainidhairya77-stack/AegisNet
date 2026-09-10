import React, { useState, useEffect } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  Play, 
  CheckCircle, 
  Search, 
  Filter, 
  ShieldCheck, 
  Activity,
  Layers,
  Flame,
  AlertTriangle
} from 'lucide-react';
import { api } from '../services/api';
import { PcapFile, NetworkFlow, AnalysisResult } from '../types';

export const PcapAnalyzer: React.FC = () => {
  const [pcaps, setPcaps] = useState<PcapFile[]>([]);
  const [selectedPcap, setSelectedPcap] = useState<PcapFile | null>(null);
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGeneratingSample, setIsGeneratingSample] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadPcaps();
  }, []);

  const loadPcaps = async () => {
    const res = await api.listPcaps();
    setPcaps(res.pcaps);
    if (res.pcaps.length > 0) {
      setSelectedPcap(res.pcaps[0]);
      loadFlows(res.pcaps[0].id);
    }
  };

  const handleLoadSampleAttack = async () => {
    setIsGeneratingSample(true);
    try {
      const samplePcap = await api.generateSampleAttack();
      setPcaps(prev => [samplePcap, ...prev]);
      setSelectedPcap(samplePcap);
      setAnalysisResult(null);
      runPipelineAnalysis(samplePcap.id);
    } finally {
      setIsGeneratingSample(false);
    }
  };

  const loadFlows = async (pcapId: string) => {
    const res = await api.getFlows(pcapId);
    setFlows(res.flows);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    try {
      const newPcap = await api.uploadPcap(file);
      setPcaps(prev => [newPcap, ...prev]);
      setSelectedPcap(newPcap);
      setAnalysisResult(null);
      // Auto trigger analysis
      runPipelineAnalysis(newPcap.id);
    } finally {
      setIsUploading(false);
    }
  };

  const runPipelineAnalysis = async (pcapId: string) => {
    setIsAnalyzing(true);
    setActiveStep(1);

    // Progressive step simulation for visual feedback
    const stepInterval = setInterval(() => {
      setActiveStep(prev => (prev < 6 ? prev + 1 : prev));
    }, 450);

    try {
      const result = await api.analyzePcap(pcapId);
      setAnalysisResult(result);
      loadFlows(pcapId);
    } finally {
      clearInterval(stepInterval);
      setActiveStep(6);
      setIsAnalyzing(false);
    }
  };

  const filteredFlows = flows.filter(f => 
    f.source_ip.includes(searchTerm) || 
    f.destination_ip.includes(searchTerm) ||
    f.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (f.destination_port && f.destination_port.toString().includes(searchTerm))
  );

  const pipelineSteps = [
    { num: 1, title: 'Scapy Packet Parsing', desc: 'Decoding L2-L4 headers & payloads' },
    { num: 2, title: 'Flow Aggregation', desc: 'Grouping into bidirectional 5-tuples' },
    { num: 3, title: 'Signature Rule Engine', desc: 'Port scans, brute force, C2 beaconing' },
    { num: 4, title: 'ML Isolation Forest', desc: 'Unsupervised anomaly detection' },
    { num: 5, title: 'Correlation Engine', desc: 'Temporal & IP-based incident linking' },
    { num: 6, title: 'Risk Score Assessment', desc: 'Multi-factor severity calculation' },
  ];

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.35rem' }}>
          PCAP Traffic & Deep Flow Analyzer
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Execute multi-stage forensic analysis on packet captures with rule-based and ML threat extraction.
        </p>
      </div>

      {/* Upload and PCAP Selection Bar */}
      <div className="cyber-card" style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <label className="btn btn-primary" style={{ cursor: 'pointer' }}>
              <UploadCloud size={16} />
              <span>{isUploading ? 'Uploading & Hashing...' : 'Upload PCAP / PCAPNG'}</span>
              <input 
                type="file" 
                accept=".pcap,.pcapng,.cap" 
                onChange={handleFileUpload} 
                style={{ display: 'none' }} 
                disabled={isUploading}
              />
            </label>

            <button
              onClick={handleLoadSampleAttack}
              disabled={isGeneratingSample || isAnalyzing}
              className="btn btn-secondary"
              style={{
                border: '1px solid var(--primary)',
                background: 'rgba(6, 182, 212, 0.08)',
                color: 'var(--primary)',
              }}
              title="Generate and replay multi-stage APT attack scenario with Scapy"
            >
              <Zap size={16} color="var(--primary)" />
              <span>{isGeneratingSample ? 'Generating Scapy Packets...' : '⚡ Load APT29 Attack Scenario'}</span>
            </button>

            <span style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>or inspect existing:</span>

            <select 
              className="input-control" 
              style={{ width: 'auto', minWidth: '260px' }}
              value={selectedPcap?.id || ''}
              onChange={(e) => {
                const found = pcaps.find(p => p.id === e.target.value);
                if (found) {
                  setSelectedPcap(found);
                  loadFlows(found.id);
                  setAnalysisResult(null);
                  setActiveStep(0);
                }
              }}
            >
              {pcaps.map(p => (
                <option key={p.id} value={p.id}>{p.original_filename}</option>
              ))}
            </select>
          </div>

          {selectedPcap && (
            <button 
              className="btn btn-secondary"
              onClick={() => runPipelineAnalysis(selectedPcap.id)}
              disabled={isAnalyzing}
            >
              <Play size={14} color="var(--primary)" />
              <span>{isAnalyzing ? 'Analyzing Traffic...' : 'Execute Full Pipeline'}</span>
            </button>
          )}
        </div>

        {selectedPcap && (
          <div style={{
            marginTop: '1.25rem',
            paddingTop: '1.25rem',
            borderTop: '1px solid var(--border-color)',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '2rem',
            fontSize: '0.8rem'
          }}>
            <div>
              <span style={{ color: 'var(--text-dim)' }}>File Size: </span>
              <span className="font-mono" style={{ fontWeight: 600 }}>
                {(selectedPcap.file_size / (1024 * 1024)).toFixed(2)} MB
              </span>
            </div>
            <div>
              <span style={{ color: 'var(--text-dim)' }}>SHA-256: </span>
              <span className="font-mono" style={{ color: 'var(--primary)' }}>
                {selectedPcap.sha256_hash}
              </span>
            </div>
            <div>
              <span style={{ color: 'var(--text-dim)' }}>Uploaded: </span>
              <span>{new Date(selectedPcap.uploaded_at).toLocaleString()}</span>
            </div>
          </div>
        )}
      </div>

      {/* Pipeline Visualizer */}
      <div className="cyber-card" style={{ marginBottom: '2rem' }}>
        <div className="cyber-card-header">
          <div className="cyber-card-title">
            <Layers size={18} color="var(--primary)" />
            <span>Multi-Stage Threat Pipeline</span>
          </div>
          {activeStep === 6 && (
            <span className="badge badge-low">Pipeline Complete</span>
          )}
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
        }}>
          {pipelineSteps.map((step) => {
            const isPassed = activeStep >= step.num;
            const isCurrent = activeStep === step.num && isAnalyzing;
            return (
              <div 
                key={step.num}
                style={{
                  background: isCurrent ? 'rgba(6, 182, 212, 0.15)' : isPassed ? 'rgba(16, 185, 129, 0.08)' : 'var(--bg-elevated)',
                  border: `1px solid ${isCurrent ? 'var(--primary)' : isPassed ? 'rgba(16, 185, 129, 0.3)' : 'var(--border-color)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '1rem',
                  position: 'relative',
                  transition: 'all 0.3s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span className="font-mono" style={{ fontSize: '0.75rem', fontWeight: 700, color: isPassed ? 'var(--success)' : 'var(--text-dim)' }}>
                    PHASE 0{step.num}
                  </span>
                  {isPassed ? (
                    <CheckCircle size={16} color="var(--success)" />
                  ) : (
                    <Activity size={16} color="var(--text-dim)" />
                  )}
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.25rem' }}>
                  {step.title}
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  {step.desc}
                </div>
              </div>
            );
          })}
        </div>

        {analysisResult && (
          <div style={{
            marginTop: '1.5rem',
            background: 'rgba(6, 182, 212, 0.05)',
            border: '1px solid var(--border-glow)',
            borderRadius: 'var(--radius-sm)',
            padding: '1rem 1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <Flame size={24} color="var(--danger)" />
              <div>
                <div style={{ fontWeight: 700, color: 'var(--text-main)' }}>Pipeline Execution Finished</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  {analysisResult.statistics.packets_parsed.toLocaleString()} packets processed • {analysisResult.statistics.flows_created} bidirectional flows extracted
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1.5rem' }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Alerts Detected</div>
                <div className="font-mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--warning)' }}>
                  {analysisResult.statistics.alerts_total}
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Incidents Correlated</div>
                <div className="font-mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--danger)' }}>
                  {analysisResult.statistics.incidents}
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Threat Score</div>
                <div className="font-mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--danger)' }}>
                  {analysisResult.statistics.risk_score}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Network Flows Table */}
      <div className="cyber-card">
        <div className="cyber-card-header">
          <div className="cyber-card-title">
            <Activity size={18} color="var(--primary)" />
            <span>Extracted Network Flows ({filteredFlows.length})</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{ position: 'relative', width: '240px' }}>
              <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '10px' }} />
              <input 
                type="text" 
                placeholder="Filter by IP, Port, Proto..." 
                className="input-control"
                style={{ paddingLeft: '2rem' }}
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="cyber-table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Source IP : Port</th>
                <th>Destination IP : Port</th>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Bytes Transferred</th>
                <th>TCP Flags</th>
                <th>Time Observed</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.map((flow) => {
                const isThreat = flow.destination_port === 4444 || flow.destination_port === 22;
                return (
                  <tr key={flow.id} style={{ background: isThreat ? 'rgba(239, 68, 68, 0.05)' : undefined }}>
                    <td className="font-mono">
                      <span style={{ color: 'var(--primary)' }}>{flow.source_ip}</span>
                      {flow.source_port && <span style={{ color: 'var(--text-dim)' }}>:{flow.source_port}</span>}
                    </td>
                    <td className="font-mono">
                      <span style={{ color: isThreat ? 'var(--danger)' : 'var(--text-main)', fontWeight: isThreat ? 600 : 400 }}>
                        {flow.destination_ip}
                      </span>
                      {flow.destination_port && <span style={{ color: 'var(--text-dim)' }}>:{flow.destination_port}</span>}
                    </td>
                    <td>
                      <span className="badge badge-cyan">{flow.protocol}</span>
                    </td>
                    <td className="font-mono">{flow.packet_count.toLocaleString()}</td>
                    <td className="font-mono">
                      {(flow.byte_count / 1024).toFixed(1)} KB
                    </td>
                    <td className="font-mono" style={{ fontSize: '0.75rem' }}>
                      {flow.tcp_flags || '—'}
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(flow.last_seen).toLocaleTimeString()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

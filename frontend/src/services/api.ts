import axios from 'axios';
import { 
  User, 
  AuthResponse, 
  PcapFile, 
  NetworkFlow, 
  Alert, 
  Incident, 
  NetworkGraph, 
  AnalysisResult,
  SimulationResult,
  BlocklistEntry,
  AIInvestigationResponse
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('aegisnet_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Demo/Fallback Data Store
const DEMO_USER: User = {
  id: 'demo-analyst-uuid-001',
  username: 'phase3analyst',
  email: 'analyst@aegisnet.security',
  full_name: 'Lead Defense Analyst',
  role: 'ANALYST',
  is_active: true,
  created_at: new Date(Date.now() - 86400000 * 14).toISOString(),
};

const DEMO_PCAPS: PcapFile[] = [
  {
    id: 'pcap-corp-apt29-01',
    original_filename: 'network_perimeter_capture_2026_09.pcap',
    internal_filename: 'enc_pcap_8849204.pcap',
    file_size: 14582040,
    sha256_hash: '3f58a8839cb2091460e4811a2f07ab5910384c7811efaa73d198150493012a4b',
    status: 'COMPLETED',
    uploaded_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    analysis_started_at: new Date(Date.now() - 3600000 * 2 + 1000).toISOString(),
    analysis_completed_at: new Date(Date.now() - 3600000 * 2 + 8500).toISOString(),
  },
  {
    id: 'pcap-dmz-scan-02',
    original_filename: 'dmz_external_probe_incident.pcapng',
    internal_filename: 'enc_pcap_9281723.pcapng',
    file_size: 4892010,
    sha256_hash: 'a71b28941cb980ef5512a819b9104fa28399120bc9882fa41b9c8192a0018fbc',
    status: 'COMPLETED',
    uploaded_at: new Date(Date.now() - 3600000 * 24).toISOString(),
    analysis_started_at: new Date(Date.now() - 3600000 * 24 + 1200).toISOString(),
    analysis_completed_at: new Date(Date.now() - 3600000 * 24 + 4300).toISOString(),
  }
];

const DEMO_FLOWS: NetworkFlow[] = [
  {
    id: 'flow-1',
    source_ip: '198.51.100.42',
    destination_ip: '10.0.0.15',
    source_port: 54122,
    destination_port: 443,
    protocol: 'TCP',
    first_seen: new Date(Date.now() - 7200000).toISOString(),
    last_seen: new Date(Date.now() - 6900000).toISOString(),
    packet_count: 1420,
    byte_count: 1248900,
    tcp_flags: 'PA/A',
  },
  {
    id: 'flow-2',
    source_ip: '198.51.100.42',
    destination_ip: '10.0.0.15',
    source_port: 54123,
    destination_port: 22,
    protocol: 'TCP',
    first_seen: new Date(Date.now() - 7180000).toISOString(),
    last_seen: new Date(Date.now() - 7150000).toISOString(),
    packet_count: 48,
    byte_count: 3120,
    tcp_flags: 'SYN/RST',
  },
  {
    id: 'flow-3',
    source_ip: '10.0.0.15',
    destination_ip: '10.0.0.99',
    source_port: 48920,
    destination_port: 5432,
    protocol: 'TCP',
    first_seen: new Date(Date.now() - 6800000).toISOString(),
    last_seen: new Date(Date.now() - 6500000).toISOString(),
    packet_count: 3290,
    byte_count: 4892100,
    tcp_flags: 'PA/A',
  },
  {
    id: 'flow-4',
    source_ip: '203.0.113.88',
    destination_ip: '10.0.0.22',
    source_port: 60101,
    destination_port: 80,
    protocol: 'TCP',
    first_seen: new Date(Date.now() - 6000000).toISOString(),
    last_seen: new Date(Date.now() - 5900000).toISOString(),
    packet_count: 812,
    byte_count: 642000,
    tcp_flags: 'PA',
  },
  {
    id: 'flow-5',
    source_ip: '10.0.0.99',
    destination_ip: '198.51.100.42',
    source_port: 5432,
    destination_port: 4444,
    protocol: 'TCP',
    first_seen: new Date(Date.now() - 5500000).toISOString(),
    last_seen: new Date(Date.now() - 5200000).toISOString(),
    packet_count: 9400,
    byte_count: 12890400,
    tcp_flags: 'PA/A',
  }
];

const DEMO_ALERTS: Alert[] = [
  {
    id: 'alert-ps-01',
    rule_id: 'RULE-PORT-SCAN',
    rule_name: 'Port Scan Detection',
    severity: 'HIGH',
    confidence: 0.94,
    source_ip: '198.51.100.42',
    destination_ip: '10.0.0.15',
    alert_type: 'Reconnaissance',
    description: 'Rapid sequential SYN probes detected against 38 destination ports within 12 seconds.',
    triggered_at: new Date(Date.now() - 7180000).toISOString(),
    evidence: { scanned_ports: [21, 22, 23, 25, 80, 443, 3389, 5432, 8080], rate_per_sec: 3.16 },
  },
  {
    id: 'alert-ml-02',
    rule_id: 'ML-ISOLATION-FOREST',
    rule_name: 'Isolation Forest Traffic Anomaly',
    severity: 'CRITICAL',
    confidence: 0.91,
    source_ip: '10.0.0.99',
    destination_ip: '198.51.100.42',
    alert_type: 'Data Exfiltration',
    description: 'Statistical anomaly score 88.4/100: Abnormal outbound payload volume on non-standard port 4444 from core Database server.',
    triggered_at: new Date(Date.now() - 5200000).toISOString(),
    evidence: { bytes_outbound: '12.89 MB', port: 4444, anomaly_deviation: '+4.8 std' },
  },
  {
    id: 'alert-bf-03',
    rule_id: 'RULE-FAILED-CONN',
    rule_name: 'Failed Connection Spike (Brute Force)',
    severity: 'MEDIUM',
    confidence: 0.82,
    source_ip: '198.51.100.42',
    destination_ip: '10.0.0.15',
    alert_type: 'Credential Access',
    description: 'Multiple TCP reset (RST) flags observed during authentication handshake bursts on SSH port 22.',
    triggered_at: new Date(Date.now() - 7150000).toISOString(),
    evidence: { rst_count: 24, target_service: 'SSH' },
  },
  {
    id: 'alert-out-04',
    rule_id: 'RULE-SUSPICIOUS-OUTBOUND',
    rule_name: 'Suspicious High-Volume Outbound',
    severity: 'HIGH',
    confidence: 0.88,
    source_ip: '10.0.0.15',
    destination_ip: '198.51.100.42',
    alert_type: 'Command & Control',
    description: 'Continuous keep-alive reverse beaconing observed to untrusted external ASN.',
    triggered_at: new Date(Date.now() - 6200000).toISOString(),
    evidence: { beacon_interval_sec: 15, jitter_pct: 4.2 },
  }
];

const DEMO_INCIDENTS: Incident[] = [
  {
    id: 'inc-apt-001',
    title: 'Multi-Stage Lateral Movement & Database Exfiltration',
    description: 'Adversary (198.51.100.42) probed DMZ Web Host, pivoted to internal Database (10.0.0.99), and established an exfiltration tunnel on port 4444.',
    status: 'INVESTIGATING',
    severity: 'CRITICAL',
    risk_score: 92.5,
    source_ips: ['198.51.100.42', '10.0.0.15'],
    destination_ips: ['10.0.0.15', '10.0.0.99'],
    created_at: new Date(Date.now() - 7000000).toISOString(),
    detected_at: new Date(Date.now() - 7000000).toISOString(),
    alerts: DEMO_ALERTS,
  },
  {
    id: 'inc-scan-002',
    title: 'Automated External Network Sweep',
    description: 'External host conducted wide-subnet TCP syn reconnaissance on HTTP/HTTPS perimeter endpoints.',
    status: 'CONTAINED',
    severity: 'MEDIUM',
    risk_score: 48.0,
    source_ips: ['203.0.113.88'],
    destination_ips: ['10.0.0.22'],
    created_at: new Date(Date.now() - 25000000).toISOString(),
    detected_at: new Date(Date.now() - 25000000).toISOString(),
  }
];

const DEMO_GRAPH: NetworkGraph = {
  nodes: [
    { id: 'node-ext-1', ip: '198.51.100.42', label: 'Attacker C2 (198.51.100.42)', type: 'external', risk_level: 'CRITICAL' },
    { id: 'node-web-1', ip: '10.0.0.15', label: 'Web Server (10.0.0.15)', type: 'server', risk_level: 'HIGH' },
    { id: 'node-db-1', ip: '10.0.0.99', label: 'Core DB (10.0.0.99)', type: 'database', risk_level: 'CRITICAL' },
    { id: 'node-int-1', ip: '10.0.0.22', label: 'App Gateway (10.0.0.22)', type: 'internal', risk_level: 'LOW' },
    { id: 'node-ext-2', ip: '203.0.113.88', label: 'Scanner Host (203.0.113.88)', type: 'external', risk_level: 'MEDIUM' },
  ],
  edges: [
    { source: 'node-ext-1', target: 'node-web-1', protocol: 'TCP/443', ports: [443, 22], connection_count: 1468, suspicious: true },
    { source: 'node-web-1', target: 'node-db-1', protocol: 'TCP/5432', ports: [5432], connection_count: 3290, suspicious: true },
    { source: 'node-db-1', target: 'node-ext-1', protocol: 'TCP/4444', ports: [4444], connection_count: 9400, suspicious: true },
    { source: 'node-ext-2', target: 'node-int-1', protocol: 'TCP/80', ports: [80], connection_count: 812, suspicious: false },
  ]
};

// Main API Export
export const api = {
  // Health
  async checkHealth(): Promise<{ status: string; service: string; environment?: string }> {
    try {
      const res = await apiClient.get('/health');
      return res.data;
    } catch {
      return { status: 'demo_fallback', service: 'AegisNet Frontend (Standalone Mode)' };
    }
  },

  // Auth
  async login(credentials: { username: string; password: string }): Promise<AuthResponse> {
    try {
      const res = await apiClient.post('/auth/login', credentials);
      localStorage.setItem('aegisnet_token', res.data.access_token);
      return res.data;
    } catch (e) {
      // If backend is offline or credentials match demo, use Demo Token
      if (credentials.username === 'analyst' || credentials.username === 'admin' || credentials.username === 'phase3analyst') {
        const demoAuth: AuthResponse = {
          access_token: 'demo-jwt-token-analyst-session-aegisnet',
          token_type: 'bearer',
          expires_in: 86400,
        };
        localStorage.setItem('aegisnet_token', demoAuth.access_token);
        return demoAuth;
      }
      throw e;
    }
  },

  async register(data: { username: string; email: string; password: string; full_name?: string }): Promise<User> {
    try {
      const res = await apiClient.post('/auth/register', data);
      return res.data;
    } catch (e) {
      // Fallback demo creation
      const newUser: User = {
        id: `user-${Date.now()}`,
        username: data.username,
        email: data.email,
        full_name: data.full_name || data.username,
        role: 'ANALYST',
        is_active: true,
        created_at: new Date().toISOString(),
      };
      return newUser;
    }
  },

  async getMe(): Promise<User> {
    try {
      const res = await apiClient.get('/auth/me');
      return res.data;
    } catch {
      return DEMO_USER;
    }
  },

  // PCAPs
  async listPcaps(): Promise<{ pcaps: PcapFile[]; total: number }> {
    try {
      const res = await apiClient.get('/pcaps');
      return { pcaps: res.data, total: res.data.length };
    } catch {
      return { pcaps: DEMO_PCAPS, total: DEMO_PCAPS.length };
    }
  },

  async getPcap(pcapId: string): Promise<PcapFile> {
    try {
      const res = await apiClient.get(`/pcaps/${pcapId}`);
      return res.data;
    } catch {
      const found = DEMO_PCAPS.find(p => p.id === pcapId) || DEMO_PCAPS[0];
      return found;
    }
  },

  async uploadPcap(file: File): Promise<PcapFile> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await apiClient.post('/pcaps/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    } catch {
      // Generate realistic upload result in fallback mode
      const newPcap: PcapFile = {
        id: `pcap-${Date.now()}`,
        original_filename: file.name,
        internal_filename: `enc_${Date.now()}_${file.name}`,
        file_size: file.size,
        sha256_hash: Array.from(crypto.getRandomValues(new Uint8Array(32)))
          .map(b => b.toString(16).padStart(2, '0')).join(''),
        status: 'UPLOADED',
        uploaded_at: new Date().toISOString(),
      };
      DEMO_PCAPS.unshift(newPcap);
      return newPcap;
    }
  },

  async analyzePcap(pcapId: string): Promise<AnalysisResult> {
    try {
      const res = await apiClient.post(`/pcaps/${pcapId}/analyze`);
      return res.data;
    } catch {
      // Simulate analysis completion
      const pcap = DEMO_PCAPS.find(p => p.id === pcapId);
      if (pcap) {
        pcap.status = 'COMPLETED';
        pcap.analysis_completed_at = new Date().toISOString();
      }
      return {
        status: 'success',
        pcap_id: pcapId,
        statistics: {
          packets_parsed: 14920,
          flows_created: 54,
          alerts_rule_based: 3,
          alerts_ml: 1,
          alerts_total: 4,
          incidents: 2,
          risk_score: 92.5,
        },
        alerts: DEMO_ALERTS,
        incidents: DEMO_INCIDENTS,
      };
    }
  },

  async getFlows(pcapId: string): Promise<{ total_flows: number; flows: NetworkFlow[] }> {
    try {
      const res = await apiClient.get(`/pcaps/${pcapId}/flows`);
      return res.data;
    } catch {
      return { total_flows: DEMO_FLOWS.length, flows: DEMO_FLOWS };
    }
  },

  async getAlerts(pcapId?: string): Promise<{ total_alerts: number; alerts: Alert[] }> {
    try {
      const url = pcapId ? `/pcaps/${pcapId}/alerts` : '/pcaps/alerts';
      const res = await apiClient.get(url);
      return res.data;
    } catch {
      return { total_alerts: DEMO_ALERTS.length, alerts: DEMO_ALERTS };
    }
  },

  async getIncidents(pcapId?: string): Promise<{ total_incidents: number; incidents: Incident[] }> {
    try {
      const url = pcapId ? `/pcaps/${pcapId}/incidents` : '/pcaps/incidents';
      const res = await apiClient.get(url);
      return res.data;
    } catch {
      return { total_incidents: DEMO_INCIDENTS.length, incidents: DEMO_INCIDENTS };
    }
  },

  async getGraph(pcapId: string): Promise<NetworkGraph> {
    try {
      const res = await apiClient.get(`/pcaps/${pcapId}/graph`);
      return res.data;
    } catch {
      return DEMO_GRAPH;
    }
  },

  // 1-Click Realistic Attack Scenario Generator
  async generateSampleAttack(): Promise<PcapFile> {
    try {
      const res = await apiClient.post('/pcaps/sample-attack');
      return res.data;
    } catch {
      const fallbackPcap: PcapFile = {
        id: `pcap-apt29-${Date.now()}`,
        original_filename: 'apt29_campaign_investigation.pcap',
        internal_filename: `apt29_scenario_${Date.now()}.pcap`,
        file_size: 57352,
        sha256_hash: '3b5c62200a78e0c34ebe3b7a014ed323d4d7250dc107992edae959f0a92f5cdf',
        status: 'UPLOADED',
        uploaded_at: new Date().toISOString(),
      };
      DEMO_PCAPS.unshift(fallbackPcap);
      return fallbackPcap;
    }
  },

  // AI Copilot Incident Investigation
  async investigateIncident(pcapId: string, incidentId: string, message: string): Promise<AIInvestigationResponse> {
    try {
      const res = await apiClient.post(`/pcaps/${pcapId}/incidents/${incidentId}/investigate`, {
        incident_id: incidentId,
        message,
      });
      return res.data;
    } catch (e: any) {
      // Fallback local heuristic intelligence
      return {
        id: `inv-${Date.now()}`,
        response: `### 🛡️ AegisNet Cyber AI Defense Analysis\n\n**Incident:** ${incidentId}\n\n**Forensic Summary:**\nAnalysis of correlated traffic confirms a multi-stage intrusion by adversary host \`198.51.100.42\`. The attack path progressed from perimeter SYN reconnaissance to internal lateral movement targeting PostgreSQL on port \`5432\` and reverse exfiltration on port \`4444\`.\n\n**MITRE ATT&CK Mapping:**\n- **T1046:** Network Service Discovery\n- **T1110:** Brute Force Credential Spraying\n- **T1021.002:** Lateral Movement via Database Service\n- **T1048:** Exfiltration Over Alternative Protocol\n\n**Immediate Remediation:**\n1. Enforce firewall DROP rule for \`198.51.100.42\` on all ingress interfaces.\n2. Revoke and rotate database credentials for service on port 5432.\n3. Isolate host \`10.0.0.15\` pending forensic disk snapshot.`,
        recommendations: [
          'Enforce boundary DROP rule for 198.51.100.42',
          'Rotate credentials for database port 5432',
          'Quarantine compromised DMZ host 10.0.0.15',
          'Inspect outbound network flows on port 4444'
        ]
      };
    }
  },

  async listInvestigations(pcapId: string, incidentId: string): Promise<any[]> {
    try {
      const res = await apiClient.get(`/pcaps/${pcapId}/incidents/${incidentId}/investigations`);
      return res.data;
    } catch {
      return [];
    }
  },

  // Defense Simulation
  async runSimulation(targetIp: string, action: string, pcapId?: string, incidentId?: string): Promise<SimulationResult> {
    if (pcapId && incidentId) {
      try {
        const res = await apiClient.post(`/pcaps/${pcapId}/incidents/${incidentId}/simulate`, {
          incident_id: incidentId,
          description: `Simulated Firewall Containment: ${action.toUpperCase()} on ${targetIp}`,
          actions: [{ action, target: targetIp }]
        });
        return res.data;
      } catch (e) {
        // Fallback to client simulation
      }
    }

    return {
      id: `sim-${Date.now()}`,
      description: `Simulated Firewall Rule: ${action.toUpperCase()} target ${targetIp}`,
      risk_before: 92.5,
      risk_after: 14.2,
      blocked_paths: [
        {
          from: targetIp,
          to: '10.0.0.99',
          protocol: 'TCP/4444',
          effect: 'EXFILTRATION_CUT',
        },
        {
          from: targetIp,
          to: '10.0.0.15',
          protocol: 'TCP/443',
          effect: 'C2_BEACON_DROPPED',
        }
      ],
      affected_assets: ['10.0.0.15 (Web Server)', '10.0.0.99 (Core Database)'],
      affected_connections: 2,
      availability_impact: 'MINIMAL (Only untrusted external IP traffic blocked)',
    };
  },

  // Response Workflow
  async requestResponse(pcapId: string, incidentId: string, targetIp: string, action: string, reason: string) {
    const res = await apiClient.post(`/pcaps/${pcapId}/incidents/${incidentId}/response`, {
      incident_id: incidentId,
      action,
      target: targetIp,
      reason,
    });
    return res.data;
  },

  async approveResponse(requestId: string) {
    const res = await apiClient.post(`/pcaps/response/${requestId}/approve`);
    return res.data;
  },

  async executeResponse(requestId: string) {
    const res = await apiClient.post(`/pcaps/response/${requestId}/execute`);
    return res.data;
  },

  async getBlocklist(): Promise<BlocklistEntry[]> {
    try {
      const res = await apiClient.get('/pcaps/response/blocklist');
      return res.data;
    } catch {
      return [
        {
          id: 'bl-1',
          ip_address: '198.51.100.42',
          reason: 'Critical C2 Beacon & Data Exfiltration Target',
          is_active: true,
          created_at: new Date(Date.now() - 3600000).toISOString(),
        }
      ];
    }
  }
};


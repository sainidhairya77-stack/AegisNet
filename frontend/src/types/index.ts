export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export type PcapStatus = 'UPLOADED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export interface PcapFile {
  id: string;
  original_filename: string;
  internal_filename: string;
  file_size: number;
  sha256_hash: string;
  status: PcapStatus;
  uploaded_at: string;
  analysis_started_at?: string | null;
  analysis_completed_at?: string | null;
  error_message?: string | null;
}

export interface NetworkFlow {
  id: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
  byte_count: number;
  tcp_flags?: string;
}

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: AlertSeverity;
  confidence: number;
  source_ip: string;
  destination_ip?: string;
  alert_type: string;
  description: string;
  triggered_at: string;
  evidence?: Record<string, any>;
}

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface Incident {
  id: string;
  title: string;
  description?: string;
  status: IncidentStatus;
  severity: AlertSeverity;
  risk_score: number;
  source_ips?: string[];
  destination_ips?: string[];
  created_at: string;
  detected_at?: string;
  alerts?: Alert[];
}

export interface GraphNode {
  id: string;
  ip: string;
  label: string;
  type: 'external' | 'internal' | 'server' | 'database';
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface GraphEdge {
  source: string;
  target: string;
  protocol: string;
  ports: number[];
  connection_count: number;
  suspicious: boolean;
}

export interface NetworkGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AttackPath {
  id: string;
  source_ip: string;
  target_ip: string;
  path_nodes: string[];
  path_edges: Record<string, any>[];
  risk_score: number;
  description?: string;
}

export interface AnalysisResult {
  status: string;
  pcap_id: string;
  statistics: {
    packets_parsed: number;
    flows_created: number;
    alerts_rule_based: number;
    alerts_ml: number;
    alerts_total: number;
    incidents: number;
    risk_score: number;
  };
  alerts: Alert[];
  incidents: Incident[];
  attack_paths?: AttackPath[];
}

export interface SimulationResult {
  id: string;
  description: string;
  risk_before: number;
  risk_after: number;
  blocked_paths: Record<string, any>[];
  affected_assets: string[];
  affected_connections: number;
  availability_impact: string;
}

export interface BlocklistEntry {
  id: string;
  ip_address: string;
  reason: string;
  is_active: boolean;
  created_at: string;
  expiration?: string | null;
}

export interface AIInvestigationResponse {
  id: string;
  response: string;
  findings?: Record<string, any>;
  recommendations?: string[];
}


"""
Pydantic schemas for request/response validation
"""

from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, field_validator
from enum import Enum

# ============================================================
# Authentication Schemas
# ============================================================


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=255)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=255)
    full_name: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        assert v.isalnum(), "Username must be alphanumeric"
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None


# ============================================================
# PCAP Schemas
# ============================================================


class PcapStatus(str, Enum):
    UPLOADED = "UPLOADED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PcapUploadResponse(BaseModel):
    id: str
    original_filename: str
    internal_filename: str
    file_size: int
    sha256_hash: str
    status: str
    uploaded_at: datetime

    class Config:
        from_attributes = True


class PcapDetail(BaseModel):
    id: str
    original_filename: str
    internal_filename: str
    file_size: int
    sha256_hash: str
    status: str
    uploaded_at: datetime
    analysis_started_at: Optional[datetime]
    analysis_completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


# ============================================================
# Network Flow Schemas
# ============================================================


class NetworkFlowResponse(BaseModel):
    id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int
    tcp_flags: Optional[str]

    class Config:
        from_attributes = True


# ============================================================
# Alert Schemas
# ============================================================


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertResponse(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    source_ip: str
    destination_ip: Optional[str]
    alert_type: str
    description: str
    triggered_at: datetime
    evidence: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


# ============================================================
# Incident Schemas
# ============================================================


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str]
    severity: str


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    status: str
    severity: str
    risk_score: float
    source_ips: Optional[List[str]]
    destination_ips: Optional[List[str]]
    created_at: datetime
    detected_at: Optional[datetime]

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    alerts: List[AlertResponse] = []


# ============================================================
# Graph Schemas
# ============================================================


class GraphNode(BaseModel):
    id: str
    ip: str
    label: str
    type: str  # external, internal, server, etc.
    risk_level: str = "LOW"


class GraphEdge(BaseModel):
    source: str
    target: str
    protocol: str
    ports: List[int]
    connection_count: int
    suspicious: bool = False


class NetworkGraph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ============================================================
# Attack Path Schemas
# ============================================================


class AttackPathResponse(BaseModel):
    id: str
    source_ip: str
    target_ip: str
    path_nodes: List[str]
    path_edges: List[Dict[str, Any]]
    risk_score: float
    description: Optional[str]

    class Config:
        from_attributes = True


# ============================================================
# AI Investigation Schemas
# ============================================================


class AIMessage(BaseModel):
    role: str  # user, assistant
    content: str


class AIInvestigationRequest(BaseModel):
    incident_id: str
    message: str


class AIInvestigationResponse(BaseModel):
    id: str
    response: str
    findings: Optional[Dict[str, Any]]
    recommendations: Optional[List[str]]


# ============================================================
# Simulation Schemas
# ============================================================


class SimulationCreate(BaseModel):
    incident_id: str
    description: str
    actions: List[Dict[str, Any]]  # List of actions to simulate


class SimulationResponse(BaseModel):
    id: str
    description: str
    risk_before: float
    risk_after: float
    blocked_paths: List[Dict[str, Any]]
    affected_assets: List[str]
    affected_connections: int
    availability_impact: str

    class Config:
        from_attributes = True


# ============================================================
# Response Schemas
# ============================================================


class ResponseStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class ResponseActionCreate(BaseModel):
    incident_id: str
    action: str  # block_ip, isolate_host, etc.
    target: str
    reason: str


class ResponseActionUpdate(BaseModel):
    approved: bool
    rejection_reason: Optional[str] = None


class ResponseActionResponse(BaseModel):
    id: str
    incident_id: str
    action: str
    target: str
    reason: str
    status: str
    created_at: datetime
    approved_at: Optional[datetime]
    executed_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================================
# Blocklist Schemas
# ============================================================


class BlocklistEntryCreate(BaseModel):
    ip_address: str
    reason: str
    expiration: Optional[datetime] = None


class BlocklistEntryResponse(BaseModel):
    id: str
    ip_address: str
    reason: str
    is_active: bool
    created_at: datetime
    expiration: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================================
# Audit Log Schemas
# ============================================================


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    result: str
    created_at: datetime
    details: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


# ============================================================
# Error Schemas
# ============================================================


class ErrorResponse(BaseModel):
    error: str
    message: str
    code: str
    details: Optional[Dict[str, Any]] = None


class ValidationErrorResponse(BaseModel):
    error: str = "Validation Error"
    details: List[Dict[str, Any]]

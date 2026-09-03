"""
AegisNet Database Models

Defines all SQLAlchemy ORM models for the application.
Uses PostgreSQL as the primary database.
"""

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Boolean, ForeignKey,
    Text, JSON, Enum as SQLEnum, Index, LargeBinary, Table
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()

# Association table for many-to-many relationship between Incident and Alert
incident_alerts = Table(
    'incident_alerts',
    Base.metadata,
    Column('incident_id', String(36), ForeignKey('incidents.id'), primary_key=True),
    Column('alert_id', String(36), ForeignKey('alerts.id'), primary_key=True)
)


class UserRole(str, enum.Enum):
    """User role enumeration"""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class AlertSeverity(str, enum.Enum):
    """Alert severity enumeration"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, enum.Enum):
    """Incident status enumeration"""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class PcapStatus(str, enum.Enum):
    """PCAP file analysis status"""
    UPLOADED = "UPLOADED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ResponseStatus(str, enum.Enum):
    """Response request status"""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class User(Base):
    """User account model"""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255))
    hashed_password = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    pcap_files = relationship("PcapFile", back_populates="uploader")
    audit_logs = relationship("AuditLog", back_populates="user")
    response_requests = relationship("ResponseRequest", foreign_keys="ResponseRequest.requester_id", back_populates="requester")
    response_approvals = relationship("ResponseRequest", foreign_keys="ResponseRequest.approved_by_id", back_populates="approver")

    __table_args__ = (
        Index("idx_user_active_created", "is_active", "created_at"),
    )


class PcapFile(Base):
    """PCAP file upload model"""
    __tablename__ = "pcap_files"

    id = Column(String(36), primary_key=True)
    original_filename = Column(String(255), nullable=False)
    internal_filename = Column(String(255), unique=True, nullable=False, index=True)
    file_path = Column(String(1024), nullable=False)
    sha256_hash = Column(String(64), unique=True, nullable=False, index=True)
    file_size = Column(Integer, nullable=False)
    status = Column(SQLEnum(PcapStatus), default=PcapStatus.UPLOADED, index=True)
    uploader_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow, index=True)
    analysis_started_at = Column(DateTime)
    analysis_completed_at = Column(DateTime)
    error_message = Column(Text)

    # Relationships
    uploader = relationship("User", back_populates="pcap_files")
    network_flows = relationship("NetworkFlow", back_populates="pcap_file", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="pcap_file", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="pcap_file")

    __table_args__ = (
        Index("idx_pcap_status_uploaded", "status", "uploaded_at"),
    )


class NetworkAsset(Base):
    """Network asset (host, server, etc.)"""
    __tablename__ = "network_assets"

    id = Column(String(36), primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    hostname = Column(String(255))
    asset_type = Column(String(50))  # workstation, server, database, etc.
    criticality = Column(String(50), default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    source_flows = relationship(
        "NetworkFlow",
        primaryjoin="NetworkAsset.ip_address == foreign(NetworkFlow.source_ip)",
        back_populates="source_asset",
    )
    dest_flows = relationship(
        "NetworkFlow",
        primaryjoin="NetworkAsset.ip_address == foreign(NetworkFlow.destination_ip)",
        back_populates="dest_asset",
    )


class NetworkFlow(Base):
    """Network flow (connection tuple)"""
    __tablename__ = "network_flows"

    id = Column(String(36), primary_key=True)
    pcap_file_id = Column(String(36), ForeignKey("pcap_files.id"), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer, index=True)
    protocol = Column(String(20), nullable=False, index=True)  # TCP, UDP, ICMP, etc.
    
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False)
    duration_seconds = Column(Float)
    
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    
    tcp_flags = Column(String(255))  # SYN, SYN-ACK, FIN, etc.
    has_retransmissions = Column(Boolean, default=False)
    has_failed_connections = Column(Boolean, default=False)

    # Relationships
    pcap_file = relationship("PcapFile", back_populates="network_flows")
    source_asset = relationship(
        "NetworkAsset",
        primaryjoin="foreign(NetworkFlow.source_ip) == NetworkAsset.ip_address",
        viewonly=True,
        back_populates="source_flows",
    )
    dest_asset = relationship(
        "NetworkAsset",
        primaryjoin="foreign(NetworkFlow.destination_ip) == NetworkAsset.ip_address",
        viewonly=True,
        back_populates="dest_flows",
    )
    detection_evidence = relationship("DetectionEvidence", back_populates="network_flow")

    __table_args__ = (
        Index("idx_flow_src_dst_port", "source_ip", "destination_ip", "destination_port"),
        Index("idx_flow_pcap_first_seen", "pcap_file_id", "first_seen"),
    )


class Alert(Base):
    """Security alert from detection rules or ML"""
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True)
    pcap_file_id = Column(String(36), ForeignKey("pcap_files.id"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(255), nullable=False)
    severity = Column(SQLEnum(AlertSeverity), nullable=False, index=True)
    confidence = Column(Float, default=1.0)  # 0.0 to 1.0
    
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20))
    
    alert_type = Column(String(100))  # rule, ml_anomaly, etc.
    description = Column(Text, nullable=False)
    evidence = Column(JSON)  # JSON structured evidence
    
    triggered_at = Column(DateTime, default=datetime.utcnow, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    pcap_file = relationship("PcapFile", back_populates="alerts")
    detection_evidence = relationship("DetectionEvidence", back_populates="alert")
    incidents = relationship("Incident", secondary="incident_alerts", back_populates="alerts")

    __table_args__ = (
        Index("idx_alert_severity_triggered", "severity", "triggered_at"),
        Index("idx_alert_source_ip", "source_ip"),
    )


class DetectionEvidence(Base):
    """Structured evidence for detection"""
    __tablename__ = "detection_evidence"

    id = Column(String(36), primary_key=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False)
    network_flow_id = Column(String(36), ForeignKey("network_flows.id"))
    
    evidence_type = Column(String(100))  # port_scan, high_conn_rate, etc.
    metric = Column(String(255))
    value = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    alert = relationship("Alert", back_populates="detection_evidence")
    network_flow = relationship("NetworkFlow", back_populates="detection_evidence")


class Incident(Base):
    """Correlated security incident"""
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True)
    pcap_file_id = Column(String(36), ForeignKey("pcap_files.id"), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True)
    
    severity = Column(SQLEnum(AlertSeverity), nullable=False)
    risk_score = Column(Float, default=0.0)  # 0 to 100
    
    source_ips = Column(JSON)  # List of involved source IPs
    destination_ips = Column(JSON)  # List of involved destination IPs
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    detected_at = Column(DateTime)

    # Relationships
    pcap_file = relationship("PcapFile", back_populates="incidents")
    alerts = relationship("Alert", secondary="incident_alerts", back_populates="incidents")
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="incident")
    response_requests = relationship("ResponseRequest", back_populates="incident")

    __table_args__ = (
        Index("idx_incident_status_created", "status", "created_at"),
        Index("idx_incident_severity_risk", "severity", "risk_score"),
    )


class IncidentEvent(Base):
    """Timeline event for an incident"""
    __tablename__ = "incident_events"

    id = Column(String(36), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    
    event_type = Column(String(100))
    description = Column(Text)
    timestamp = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="events")


class AttackPath(Base):
    """Possible attack path in network"""
    __tablename__ = "attack_paths"

    id = Column(String(36), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False, index=True)
    
    source_ip = Column(String(45), nullable=False)
    target_ip = Column(String(45), nullable=False)
    
    path_nodes = Column(JSON)  # List of IPs in path
    path_edges = Column(JSON)  # List of connections
    
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.5)
    
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="attack_paths")


class Simulation(Base):
    """What-if simulation of defensive action"""
    __tablename__ = "simulations"

    id = Column(String(36), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    
    description = Column(String(255), nullable=False)
    
    risk_before = Column(Float, default=0.0)
    risk_after = Column(Float, default=0.0)
    
    blocked_paths = Column(JSON)  # Attack paths that would be blocked
    affected_assets = Column(JSON)
    affected_connections = Column(Integer, default=0)
    
    availability_impact = Column(String(50))  # LOW, MEDIUM, HIGH
    results = Column(JSON)  # Detailed simulation results
    
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_id = Column(String(36), ForeignKey("users.id"))


class ResponseRequest(Base):
    """Request for defensive response action"""
    __tablename__ = "response_requests"

    id = Column(String(36), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False, index=True)
    
    action = Column(String(100), nullable=False)  # block_ip, isolate_host, etc.
    target = Column(String(255), nullable=False)  # IP, hostname, etc.
    reason = Column(Text, nullable=False)
    
    status = Column(SQLEnum(ResponseStatus), default=ResponseStatus.PENDING, index=True)
    
    requester_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by_id = Column(String(36), ForeignKey("users.id"))
    approved_at = Column(DateTime)
    rejection_reason = Column(Text)
    
    executed_at = Column(DateTime)
    execution_result = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="response_requests")
    requester = relationship("User", foreign_keys=[requester_id], back_populates="response_requests")
    approver = relationship("User", foreign_keys=[approved_by_id], back_populates="response_approvals")


class BlocklistEntry(Base):
    """IP blocklist entry"""
    __tablename__ = "blocklist_entries"

    id = Column(String(36), primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(Text, nullable=False)
    source_incident_id = Column(String(36), ForeignKey("incidents.id"))
    
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expiration = Column(DateTime)
    is_active = Column(Boolean, default=True, index=True)


class AuditLog(Base):
    """Audit log for security-sensitive actions"""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"))
    
    action = Column(String(255), nullable=False)  # login, upload, analyze, etc.
    resource_type = Column(String(100))  # user, pcap, incident, etc.
    resource_id = Column(String(36))
    
    details = Column(JSON)
    result = Column(String(50))  # success, failure
    error_message = Column(Text)
    
    source_ip = Column(String(45))
    user_agent = Column(String(512))
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_user_created", "user_id", "created_at"),
        Index("idx_audit_action_created", "action", "created_at"),
    )


class AIInvestigation(Base):
    """AI investigation session"""
    __tablename__ = "ai_investigations"

    id = Column(String(36), primary_key=True)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    
    user_id = Column(String(36), ForeignKey("users.id"))
    conversation = Column(JSON)  # Message history
    
    summary = Column(Text)
    findings = Column(JSON)
    recommendations = Column(JSON)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

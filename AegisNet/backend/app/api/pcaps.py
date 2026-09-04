"""
PCAP upload and analysis API routes
"""

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import PcapFile
from app.schemas import AttackPathResponse, NetworkGraph, PcapUploadResponse, PcapDetail
from app.services.pcap_service import PcapFileService
from app.services.packet_parser import PacketParser, FlowAggregator, PcapParseError
from app.services.rule_engine import RuleEngine
from app.services.ml_engine import MLDetectionEngine
from app.services.correlation_engine import IncidentCorrelator
from app.services.graph_engine import AttackPathAnalyzer, NetworkTopologyBuilder
from app.security import get_current_user, get_current_analyst
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pcaps", tags=["PCAP Analysis"])


@router.post("/upload", response_model=PcapUploadResponse)
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_analyst)
):
    """
    Upload a PCAP file for analysis
    
    - Validates file extension and size
    - Saves file securely with unique name
    - Creates database record
    - Returns upload metadata
    """
    # Validate upload
    is_valid, error_msg = PcapFileService.validate_upload(file)
    if not is_valid:
        logger.warning(f"Invalid PCAP upload: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )

    # Save file
    try:
        internal_filename, file_path, sha256_hash, file_size = PcapFileService.save_uploaded_file(file)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save PCAP file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save PCAP file"
        )

    # Create database record
    pcap = PcapFileService.create_pcap_record(
        db=db,
        original_filename=file.filename,
        internal_filename=internal_filename,
        file_path=file_path,
        sha256_hash=sha256_hash,
        file_size=file_size,
        uploader_id=user_id
    )

    logger.info(f"PCAP uploaded by {user_id}: {pcap.id}")

    return pcap


@router.get("/{pcap_id}/graph", response_model=NetworkGraph)
async def get_pcap_graph(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Build observed network topology from analyzed PCAP flows."""
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    return NetworkTopologyBuilder.build_graph(db, pcap_id)


@router.post("/{pcap_id}/analyze")
@router.post("/analyze/{pcap_id}", include_in_schema=False)
async def analyze_pcap(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_analyst)
):
    """
    Trigger analysis of uploaded PCAP file
    
    Full detection pipeline:
    1. Parse packets and extract network flows
    2. Run rule-based detection
    3. Run ML anomaly detection
    4. Correlate alerts into incidents
    5. Calculate risk scores
    
    Note: This is simplified. In production, this would be async/queued.
    """
    # Get PCAP file
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PCAP not found"
        )

    # Update status to processing
    PcapFileService.update_status(db, pcap_id, "PROCESSING")

    try:
        logger.info(f"Starting analysis of PCAP: {pcap_id}")
        
        # Step 1: Parse PCAP and create flows
        parser = PacketParser()
        packets = parser.parse_pcap_file(pcap.file_path)
        logger.info(f"Parsed {len(packets)} packets")

        # Step 3: Aggregate into network flows
        aggregator = FlowAggregator()
        flows = aggregator.create_flows(packets)
        aggregator.save_flows(db, pcap_id, flows)
        persisted_flows = FlowAggregator.get_flows_for_pcap(db, pcap_id)
        
        flow_count = len(flows)
        logger.info(f"Aggregated into {flow_count} flows")

        # Step 4: Run rule-based detection
        rule_engine = RuleEngine()
        rule_alerts_data = rule_engine.detect(persisted_flows)
        rule_engine.save_alerts(db, pcap_id, rule_alerts_data)
        logger.info(f"Rule-based detection found {len(rule_alerts_data)} alerts")

        # Step 5: Run ML anomaly detection
        ml_engine = MLDetectionEngine()
        ml_alerts_data = ml_engine.detect(persisted_flows, threshold=70)
        ml_engine.save_alerts(db, pcap_id, ml_alerts_data)
        logger.info(f"ML anomaly detection found {len(ml_alerts_data)} alerts")

        # Step 6: Combine alerts
        from app.models import Alert
        all_alerts = db.query(Alert).filter(Alert.pcap_file_id == pcap_id).all()
        alert_count = len(all_alerts)
        logger.info(f"Total alerts: {alert_count}")

        # Step 7: Correlate alerts into incidents
        incident_count = 0
        incident_risks = []
        
        if all_alerts:
            correlator = IncidentCorrelator()
            incidents = correlator.correlate_alerts(db, pcap_id, all_alerts)
            incident_count = len(incidents)
            
            # Get incident risk scores
            for incident in incidents:
                incident_risks.append({
                    "id": incident.id,
                    "title": incident.title,
                    "risk_score": incident.risk_score,
                    "severity": incident.severity.value if incident.severity else "UNKNOWN",
                    "alert_count": len(incident.alerts)
                })
            
            logger.info(f"Correlated into {incident_count} incidents")

        # Update PCAP status
        PcapFileService.update_status(db, pcap_id, "COMPLETED")

        logger.info(f"PCAP analysis completed: {pcap_id}")

        return {
            "status": "success",
            "pcap_id": pcap_id,
            "statistics": {
                "packets_parsed": len(packets),
                "flows_created": flow_count,
                "alerts_rule_based": len(rule_alerts_data),
                "alerts_ml_based": len(ml_alerts_data),
                "alerts_total": alert_count,
                "incidents": incident_count
            },
            "incidents": incident_risks,
            "message": f"Analysis complete: {flow_count} flows, {alert_count} alerts, {incident_count} incidents"
        }

    except PcapParseError as e:
        error_message = str(e)
        logger.warning(f"PCAP analysis rejected: {pcap_id}: {error_message}")
        PcapFileService.update_status(db, pcap_id, "FAILED", error_message)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    except Exception as e:
        logger.error(f"PCAP analysis failed: {str(e)}", exc_info=True)
        PcapFileService.update_status(db, pcap_id, "FAILED", str(e))

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PCAP analysis failed: {str(e)}"
        )


@router.get("/", response_model=List[PcapDetail])
async def list_pcaps(
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    """List PCAP files uploaded by current user"""
    pcaps = PcapFileService.list_pcaps(db, user_id=user_id, limit=limit, offset=offset)
    return pcaps


@router.get("/{pcap_id}", response_model=PcapDetail)
async def get_pcap(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Get details of a specific PCAP file"""
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PCAP not found"
        )

    # Check authorization (only uploader or admin can view)
    if pcap.uploader_id != user_id:
        # TODO: Check if user is admin
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this PCAP"
        )

    return pcap


@router.get("/{pcap_id}/flows")
async def get_pcap_flows(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Get network flows from analyzed PCAP"""
    # Verify PCAP exists and user has access
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get flows
    from app.services.packet_parser import FlowAggregator
    flows = FlowAggregator.get_flows_for_pcap(db, pcap_id)

    return {
        "pcap_id": pcap_id,
        "total_flows": len(flows),
        "flows": [
            {
                "id": f.id,
                "source_ip": f.source_ip,
                "destination_ip": f.destination_ip,
                "source_port": f.source_port,
                "destination_port": f.destination_port,
                "protocol": f.protocol,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
                "duration_seconds": f.duration_seconds
            }
            for f in flows[offset:offset + limit]
        ]
    }


@router.get("/{pcap_id}/alerts")
async def get_pcap_alerts(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: str = Query(None)
):
    """Get alerts detected in analyzed PCAP"""
    from app.models import Alert
    
    # Verify PCAP exists
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Query alerts
    query = db.query(Alert).filter(Alert.pcap_file_id == pcap_id)
    
    # Optional severity filter
    if severity:
        query = query.filter(Alert.severity == severity)
    
    total = query.count()
    alerts = query.order_by(Alert.triggered_at.desc()).offset(offset).limit(limit).all()

    return {
        "pcap_id": pcap_id,
        "total_alerts": total,
        "alerts": [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "description": a.description,
                "severity": a.severity.value if a.severity else "UNKNOWN",
                "confidence": a.confidence,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "triggered_at": a.triggered_at
            }
            for a in alerts
        ]
    }


@router.get("/{pcap_id}/incidents")
async def get_pcap_incidents(
    pcap_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """Get incidents correlated from alerts in PCAP"""
    from app.models import Incident
    
    # Verify PCAP exists
    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Query incidents
    query = db.query(Incident).filter(Incident.pcap_file_id == pcap_id)
    total = query.count()
    incidents = query.order_by(Incident.detected_at.desc()).offset(offset).limit(limit).all()

    return {
        "pcap_id": pcap_id,
        "total_incidents": total,
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
                "description": i.description,
                "severity": i.severity.value if i.severity else "UNKNOWN",
                "risk_score": i.risk_score,
                "alert_count": len(i.alerts),
                "source_ips": i.source_ips,
                "destination_ips": i.destination_ips,
                "detected_at": i.detected_at,
                "created_at": i.created_at
            }
            for i in incidents
        ]
    }


@router.post("/{pcap_id}/incidents/{incident_id}/attack-paths", response_model=List[AttackPathResponse])
async def analyze_incident_attack_paths(
    pcap_id: str,
    incident_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_analyst)
):
    """Find observed paths from incident sources to critical or impacted assets."""
    from app.models import Incident

    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.pcap_file_id == pcap_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return AttackPathAnalyzer.analyze_incident(db, incident)


@router.get("/{pcap_id}/incidents/{incident_id}/attack-paths", response_model=List[AttackPathResponse])
async def get_incident_attack_paths(
    pcap_id: str,
    incident_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Retrieve previously calculated attack paths for an incident."""
    from app.models import Incident

    pcap = PcapFileService.get_pcap(db, pcap_id)
    if not pcap:
        raise HTTPException(status_code=404, detail="PCAP not found")

    if pcap.uploader_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.pcap_file_id == pcap_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return AttackPathAnalyzer.list_for_incident(db, incident_id)

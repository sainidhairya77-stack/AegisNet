"""
Incident Correlation Engine

Groups related alerts into incidents
"""

from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional
from uuid import uuid4
from sqlalchemy.orm import Session
import logging

from app.models import Alert, Incident, IncidentEvent, AlertSeverity
from app.services.risk_engine import RiskCalculator

logger = logging.getLogger(__name__)


class IncidentCorrelator:
    """Correlate related alerts into incidents"""

    # Time window for correlation (seconds)
    CORRELATION_WINDOW = 3600  # 1 hour

    # IP similarity threshold (how many IPs must be shared)
    IP_CORRELATION_THRESHOLD = 1

    @staticmethod
    def correlate_alerts(db: Session, pcap_id: str, alerts: List[Alert]) -> List[Incident]:
        """
        Correlate related alerts into incidents
        
        Returns:
            List of created incidents
        """
        if not alerts:
            return []

        created_incidents = []

        # Group alerts by correlation
        alert_groups = IncidentCorrelator._group_alerts(alerts)

        # Create incident for each group
        for group_idx, group_alerts in enumerate(alert_groups):
            incident = IncidentCorrelator._create_incident(
                db, pcap_id, group_alerts
            )
            created_incidents.append(incident)

            logger.info(f"Created incident {incident.id} with {len(group_alerts)} alerts")

        return created_incidents

    @staticmethod
    def _group_alerts(alerts: List[Alert]) -> List[List[Alert]]:
        """
        Group related alerts
        
        Correlation factors:
        - Shared source/destination IPs
        - Time proximity
        - Alert type similarity
        
        Returns:
            List of alert groups
        """
        if not alerts:
            return []

        groups = []
        processed = set()

        # Sort by time
        sorted_alerts = sorted(alerts, key=lambda a: a.triggered_at)

        for i, alert in enumerate(sorted_alerts):
            if i in processed:
                continue

            # Start new group
            current_group = [alert]
            processed.add(i)

            # Find related alerts
            for j, other_alert in enumerate(sorted_alerts[i + 1:], start=i + 1):
                if j in processed:
                    continue

                if IncidentCorrelator._alerts_correlated(alert, other_alert):
                    current_group.append(other_alert)
                    processed.add(j)

            groups.append(current_group)

        return groups

    @staticmethod
    def _alerts_correlated(alert1: Alert, alert2: Alert) -> bool:
        """Check if two alerts should be correlated"""
        # Time correlation
        time_diff = (alert2.triggered_at - alert1.triggered_at).total_seconds()
        if time_diff > IncidentCorrelator.CORRELATION_WINDOW:
            return False

        # IP correlation
        ips_match = (
            (alert1.source_ip == alert2.source_ip) or
            (alert1.source_ip == alert2.destination_ip) or
            (alert1.destination_ip == alert2.source_ip) or
            (alert1.destination_ip == alert2.destination_ip)
        )

        if not ips_match:
            return False

        return True

    @staticmethod
    def _create_incident(
        db: Session, pcap_id: str, alerts: List[Alert]
    ) -> Incident:
        """Create incident from alert group"""
        # Extract metadata
        source_ips = set(a.source_ip for a in alerts if a.source_ip)
        dest_ips = set(a.destination_ip for a in alerts if a.destination_ip)

        # Determine severity
        severities = [a.severity for a in alerts]
        if AlertSeverity.CRITICAL in severities:
            severity = AlertSeverity.CRITICAL
        elif AlertSeverity.HIGH in severities:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM

        # Calculate risk score
        risk_score = RiskCalculator.calculate_incident_risk(
            db, alerts, list(source_ips), list(dest_ips)
        )

        # Create title
        if len(alerts) == 1:
            title = alerts[0].rule_name
        else:
            title = f"Correlated Incident: {' + '.join(set(a.rule_name for a in alerts[:2]))}"

        # Build description
        description_lines = [f"Incident with {len(alerts)} correlated alerts:"]
        for alert in alerts[:3]:
            description_lines.append(f"- {alert.description}")
        if len(alerts) > 3:
            description_lines.append(f"- ... and {len(alerts) - 3} more alerts")

        # Create incident
        incident = Incident(
            id=str(uuid4()),
            pcap_file_id=pcap_id,
            title=title,
            description="\n".join(description_lines),
            severity=severity,
            risk_score=risk_score,
            source_ips=list(source_ips),
            destination_ips=list(dest_ips),
            created_at=datetime.utcnow(),
            detected_at=alerts[0].triggered_at
        )

        db.add(incident)
        db.flush()  # Get incident ID

        # Add alerts to incident
        for alert in alerts:
            # Create association
            incident.alerts.append(alert)

        # Create timeline event
        event = IncidentEvent(
            id=str(uuid4()),
            incident_id=incident.id,
            event_type="created",
            description=f"Incident created with {len(alerts)} correlated alerts",
            timestamp=datetime.utcnow()
        )
        db.add(event)

        db.commit()
        db.refresh(incident)

        return incident


class IncidentAnalyzer:
    """Analyze incident characteristics"""

    @staticmethod
    def analyze_incident(db: Session, incident: Incident) -> Dict:
        """
        Analyze incident and provide summary
        
        Returns:
            Incident analysis data
        """
        return {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity.value if incident.severity else "UNKNOWN",
            "risk_score": incident.risk_score,
            "status": incident.status.value if incident.status else "OPEN",
            "alert_count": len(incident.alerts),
            "involved_ips": {
                "sources": incident.source_ips,
                "destinations": incident.destination_ips
            },
            "timeline": {
                "created_at": incident.created_at,
                "detected_at": incident.detected_at,
                "events": len(incident.events)
            },
            "top_threats": IncidentAnalyzer._get_top_threats(incident)
        }

    @staticmethod
    def _get_top_threats(incident: Incident) -> List[Dict]:
        """Extract top threat indicators from incident"""
        threats = []

        for alert in incident.alerts[:5]:
            threats.append({
                "type": alert.rule_name,
                "severity": alert.severity.value,
                "confidence": alert.confidence,
                "description": alert.description
            })

        return threats

"""
Risk Scoring Engine

Calculates comprehensive risk scores from multiple sources of evidence
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
from sqlalchemy.orm import Session
import logging

from app.models import Alert, AlertSeverity, NetworkAsset

logger = logging.getLogger(__name__)


class RiskCalculator:
    """Calculate risk scores from security evidence"""

    # Severity weights
    SEVERITY_WEIGHTS = {
        AlertSeverity.CRITICAL: 1.0,
        AlertSeverity.HIGH: 0.75,
        AlertSeverity.MEDIUM: 0.5,
        AlertSeverity.LOW: 0.25
    }

    # Risk score thresholds
    RISK_THRESHOLDS = {
        AlertSeverity.CRITICAL: 90,
        AlertSeverity.HIGH: 70,
        AlertSeverity.MEDIUM: 50,
        AlertSeverity.LOW: 30
    }

    @staticmethod
    def calculate_alert_risk(alert: Alert) -> float:
        """
        Calculate risk contribution from a single alert
        
        Returns:
            Risk score 0-100
        """
        # Base score from severity
        severity_weight = RiskCalculator.SEVERITY_WEIGHTS.get(alert.severity, 0.5)

        # Confidence adjustment
        confidence_factor = alert.confidence if alert.confidence else 0.5

        # Combined score
        risk_score = (severity_weight * 100) * confidence_factor

        return min(100, max(0, risk_score))

    @staticmethod
    def calculate_incident_risk(
        db: Session,
        alerts: List[Alert],
        source_ips: Optional[List[str]] = None,
        destination_ips: Optional[List[str]] = None
    ) -> float:
        """
        Calculate overall incident risk score
        
        Factors:
        - Alert severity and confidence
        - Number of alerts
        - Asset criticality
        - Evidence correlation
        
        Returns:
            Risk score 0-100
        """
        if not alerts:
            return 0.0

        # Base score from alerts
        alert_scores = [RiskCalculator.calculate_alert_risk(alert) for alert in alerts]
        avg_alert_score = sum(alert_scores) / len(alert_scores)

        # Boost for multiple alerts
        alert_count_boost = min(20, len(alerts) * 2)  # +2% per alert, max +20%

        # Asset criticality adjustment
        criticality_boost = RiskCalculator._calculate_criticality_boost(
            db, source_ips, destination_ips
        )

        # Combine factors
        combined_score = (
            (avg_alert_score * 0.6) +
            (alert_count_boost * 0.2) +
            (criticality_boost * 0.2)
        )

        return min(100, max(0, combined_score))

    @staticmethod
    def _calculate_criticality_boost(
        db: Session,
        source_ips: Optional[List[str]] = None,
        destination_ips: Optional[List[str]] = None
    ) -> float:
        """
        Calculate risk boost based on asset criticality
        
        Returns:
            Boost value 0-100
        """
        boost = 0

        # Check destination assets (more important)
        if destination_ips:
            for ip in destination_ips:
                asset = db.query(NetworkAsset).filter(NetworkAsset.ip_address == ip).first()
                if asset:
                    if asset.criticality == "CRITICAL":
                        boost += 30
                    elif asset.criticality == "HIGH":
                        boost += 20
                    elif asset.criticality == "MEDIUM":
                        boost += 10

        return min(100, boost)

    @staticmethod
    def severity_to_risk(severity: AlertSeverity) -> float:
        """Convert severity level to baseline risk score"""
        return RiskCalculator.RISK_THRESHOLDS.get(severity, 50)

    @staticmethod
    def risk_to_severity(risk_score: float) -> AlertSeverity:
        """Convert risk score to severity level"""
        if risk_score >= 90:
            return AlertSeverity.CRITICAL
        elif risk_score >= 70:
            return AlertSeverity.HIGH
        elif risk_score >= 50:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW


class RiskExplainer:
    """Explain risk score contributors"""

    @staticmethod
    def explain_risk(
        alerts: List[Alert],
        source_ips: Optional[List[str]] = None,
        destination_ips: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate explanation for risk score
        
        Returns:
            Dictionary with risk factors and contributions
        """
        explanation = {
            "factors": [],
            "total_alerts": len(alerts),
            "high_severity_alerts": sum(1 for a in alerts if a.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)),
            "top_alert": None,
            "evidence_summary": []
        }

        # Top alert
        if alerts:
            top_alert = max(alerts, key=lambda a: RiskCalculator.calculate_alert_risk(a))
            explanation["top_alert"] = {
                "rule": top_alert.rule_name,
                "description": top_alert.description,
                "severity": top_alert.severity.value
            }

        # Factor breakdown
        if len(alerts) > 1:
            explanation["factors"].append({
                "name": "Multiple alerts",
                "impact": "high",
                "description": f"{len(alerts)} different detections correlate to increase confidence"
            })

        # High severity factors
        critical_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        if critical_alerts:
            explanation["factors"].append({
                "name": "Critical severity detections",
                "impact": "critical",
                "description": f"{len(critical_alerts)} critical-severity alerts detected"
            })

        # Evidence summary
        for alert in alerts[:5]:  # Top 5 alerts
            explanation["evidence_summary"].append({
                "rule": alert.rule_name,
                "description": alert.description,
                "confidence": alert.confidence
            })

        return explanation

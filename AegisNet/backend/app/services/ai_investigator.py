"""
AI-assisted incident investigation service.
"""

from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AIInvestigation, Alert, AttackPath, Incident


class AIInvestigator:
    """Prepare incident evidence and request an OpenAI investigation."""

    @staticmethod
    def investigate(db: Session, incident: Incident, message: str, user_id: str) -> AIInvestigation:
        settings = get_settings()
        if not settings.openai_configured:
            raise RuntimeError("OpenAI API key is not configured")

        evidence = AIInvestigator._build_evidence(db, incident)
        prompt = AIInvestigator._build_prompt(incident, evidence, message)

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("OpenAI SDK is not installed") from exc

        client = OpenAI(api_key=settings.openai_api_key)
        response = client.responses.create(
            model=settings.openai_model,
            input=prompt,
            max_output_tokens=settings.openai_max_tokens,
        )

        response_text = getattr(response, "output_text", None)
        if not response_text:
            response_text = str(response)

        investigation = AIInvestigation(
            id=str(uuid4()),
            incident_id=incident.id,
            user_id=user_id,
            conversation=[
                {"role": "user", "content": message},
                {"role": "assistant", "content": response_text},
            ],
            summary=response_text,
            findings=evidence,
            recommendations=AIInvestigator._extract_recommendations(response_text),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(investigation)
        db.commit()
        db.refresh(investigation)
        return investigation

    @staticmethod
    def list_for_incident(db: Session, incident_id: str) -> List[AIInvestigation]:
        return (
            db.query(AIInvestigation)
            .filter(AIInvestigation.incident_id == incident_id)
            .order_by(AIInvestigation.created_at.desc())
            .all()
        )

    @staticmethod
    def _build_evidence(db: Session, incident: Incident) -> Dict[str, Any]:
        alerts = (
            db.query(Alert)
            .filter(Alert.pcap_file_id == incident.pcap_file_id)
            .order_by(Alert.triggered_at.desc())
            .limit(25)
            .all()
        )
        paths = (
            db.query(AttackPath)
            .filter(AttackPath.incident_id == incident.id)
            .order_by(AttackPath.risk_score.desc())
            .limit(10)
            .all()
        )

        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity.value if incident.severity else "UNKNOWN",
                "risk_score": incident.risk_score,
                "source_ips": incident.source_ips or [],
                "destination_ips": incident.destination_ips or [],
            },
            "alerts": [
                {
                    "rule_name": alert.rule_name,
                    "severity": alert.severity.value if alert.severity else "UNKNOWN",
                    "confidence": alert.confidence,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "description": alert.description,
                    "evidence": alert.evidence or {},
                }
                for alert in alerts
            ],
            "attack_paths": [
                {
                    "source_ip": path.source_ip,
                    "target_ip": path.target_ip,
                    "risk_score": path.risk_score,
                    "path_nodes": path.path_nodes,
                    "path_edges": path.path_edges,
                }
                for path in paths
            ],
        }

    @staticmethod
    def _build_prompt(incident: Incident, evidence: Dict[str, Any], message: str) -> str:
        return (
            "You are AegisNet's cybersecurity investigation assistant. "
            "Analyze only the supplied evidence. Be concise, separate facts from hypotheses, "
            "and recommend analyst-verifiable next steps.\n\n"
            f"Analyst question: {message}\n\n"
            f"Incident title: {incident.title}\n"
            f"Evidence: {evidence}"
        )

    @staticmethod
    def _extract_recommendations(response_text: str) -> List[str]:
        recommendations = []
        for line in response_text.splitlines():
            stripped = line.strip(" -\t")
            if stripped:
                recommendations.append(stripped)
            if len(recommendations) == 5:
                break
        return recommendations

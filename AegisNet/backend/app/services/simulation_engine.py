"""
Digital twin simulation service for defensive actions.
"""

from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import Incident, NetworkFlow, Simulation


class DigitalTwinSimulator:
    """Simulate response actions against observed PCAP connectivity."""

    SUPPORTED_ACTIONS = {"block_ip", "isolate_host"}

    @staticmethod
    def simulate(
        db: Session,
        incident: Incident,
        description: str,
        actions: List[Dict[str, Any]],
        user_id: str,
    ) -> Simulation:
        normalized_actions = DigitalTwinSimulator._validate_actions(actions)
        flows = db.query(NetworkFlow).filter(NetworkFlow.pcap_file_id == incident.pcap_file_id).all()

        blocked_flows = []
        blocked_paths = []
        affected_assets = set()

        for flow in flows:
            if DigitalTwinSimulator._flow_blocked(flow, normalized_actions):
                blocked_flows.append(flow)
                affected_assets.add(flow.source_ip)
                affected_assets.add(flow.destination_ip)

        for path in incident.attack_paths:
            path_nodes = path.path_nodes or []
            if any(DigitalTwinSimulator._ip_targeted(ip, normalized_actions) for ip in path_nodes):
                blocked_paths.append({
                    "attack_path_id": path.id,
                    "source_ip": path.source_ip,
                    "target_ip": path.target_ip,
                    "path_nodes": path_nodes,
                    "risk_score": path.risk_score,
                })

        risk_before = float(incident.risk_score or 0)
        reduction = min(60.0, len(blocked_flows) * 3.0 + len(blocked_paths) * 10.0)
        risk_after = max(0.0, risk_before - reduction)

        simulation = Simulation(
            id=str(uuid4()),
            incident_id=incident.id,
            description=description,
            risk_before=risk_before,
            risk_after=risk_after,
            blocked_paths=blocked_paths,
            affected_assets=sorted(affected_assets),
            affected_connections=len(blocked_flows),
            availability_impact=DigitalTwinSimulator._availability_impact(len(blocked_flows), len(flows)),
            results={
                "actions": normalized_actions,
                "observed_connections": len(flows),
                "blocked_connections": len(blocked_flows),
                "risk_delta": risk_before - risk_after,
            },
            created_at=datetime.utcnow(),
            created_by_id=user_id,
        )
        db.add(simulation)
        db.commit()
        db.refresh(simulation)
        return simulation

    @staticmethod
    def list_for_incident(db: Session, incident_id: str) -> List[Simulation]:
        return (
            db.query(Simulation)
            .filter(Simulation.incident_id == incident_id)
            .order_by(Simulation.created_at.desc())
            .all()
        )

    @staticmethod
    def _validate_actions(actions: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        normalized = []
        for action in actions:
            action_type = str(action.get("action", "")).strip()
            target = str(action.get("target", "")).strip()
            if action_type not in DigitalTwinSimulator.SUPPORTED_ACTIONS:
                raise ValueError(f"Unsupported simulation action: {action_type}")
            if not target:
                raise ValueError("Simulation action target is required")
            normalized.append({"action": action_type, "target": target})
        if not normalized:
            raise ValueError("At least one simulation action is required")
        return normalized

    @staticmethod
    def _flow_blocked(flow: NetworkFlow, actions: List[Dict[str, str]]) -> bool:
        return any(
            action["target"] in {flow.source_ip, flow.destination_ip}
            for action in actions
        )

    @staticmethod
    def _ip_targeted(ip: str, actions: List[Dict[str, str]]) -> bool:
        return any(action["target"] == ip for action in actions)

    @staticmethod
    def _availability_impact(blocked_count: int, total_count: int) -> str:
        if total_count == 0 or blocked_count == 0:
            return "LOW"
        ratio = blocked_count / total_count
        if ratio >= 0.5:
            return "HIGH"
        if ratio >= 0.2:
            return "MEDIUM"
        return "LOW"

"""
Controlled response workflow and firewall connector services.
"""

from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import BlocklistEntry, Incident, ResponseRequest, ResponseStatus


class FirewallConnector:
    """Execute approved response actions through the configured firewall mode."""

    @staticmethod
    def execute(db: Session, request: ResponseRequest, executor_id: str) -> Dict[str, Any]:
        settings = get_settings()
        if settings.firewall_is_mock:
            return FirewallConnector._execute_mock(db, request, executor_id)
        raise RuntimeError("Linux firewall connector is not available in this environment")

    @staticmethod
    def _execute_mock(db: Session, request: ResponseRequest, executor_id: str) -> Dict[str, Any]:
        if request.action == "block_ip":
            existing = (
                db.query(BlocklistEntry)
                .filter(BlocklistEntry.ip_address == request.target, BlocklistEntry.is_active.is_(True))
                .first()
            )
            if not existing:
                db.add(BlocklistEntry(
                    id=str(uuid4()),
                    ip_address=request.target,
                    reason=request.reason,
                    source_incident_id=request.incident_id,
                    created_by_id=executor_id,
                    created_at=datetime.utcnow(),
                    is_active=True,
                ))

        elif request.action == "isolate_host":
            existing = (
                db.query(BlocklistEntry)
                .filter(BlocklistEntry.ip_address == request.target, BlocklistEntry.is_active.is_(True))
                .first()
            )
            if not existing:
                db.add(BlocklistEntry(
                    id=str(uuid4()),
                    ip_address=request.target,
                    reason=f"Host isolation requested: {request.reason}",
                    source_incident_id=request.incident_id,
                    created_by_id=executor_id,
                    created_at=datetime.utcnow(),
                    is_active=True,
                ))
        else:
            raise ValueError(f"Unsupported response action: {request.action}")

        return {
            "mode": "mock",
            "action": request.action,
            "target": request.target,
            "result": "applied",
        }


class ResponseEngine:
    """Create, approve, and execute controlled defensive responses."""

    SUPPORTED_ACTIONS = {"block_ip", "isolate_host"}

    @staticmethod
    def create_request(
        db: Session,
        incident: Incident,
        action: str,
        target: str,
        reason: str,
        requester_id: str,
    ) -> ResponseRequest:
        if action not in ResponseEngine.SUPPORTED_ACTIONS:
            raise ValueError(f"Unsupported response action: {action}")
        if not target:
            raise ValueError("Response target is required")
        if not reason:
            raise ValueError("Response reason is required")

        request = ResponseRequest(
            id=str(uuid4()),
            incident_id=incident.id,
            action=action,
            target=target,
            reason=reason,
            status=ResponseStatus.PENDING,
            requester_id=requester_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(request)
        db.commit()
        db.refresh(request)
        return request

    @staticmethod
    def approve(db: Session, request: ResponseRequest, approved: bool, approver_id: str, rejection_reason: str = None) -> ResponseRequest:
        if request.status != ResponseStatus.PENDING:
            raise ValueError("Only pending response requests can be reviewed")

        request.approved_by_id = approver_id
        request.approved_at = datetime.utcnow()
        request.updated_at = datetime.utcnow()
        if approved:
            request.status = ResponseStatus.APPROVED
            request.rejection_reason = None
        else:
            request.status = ResponseStatus.REJECTED
            request.rejection_reason = rejection_reason or "Rejected by approver"

        db.commit()
        db.refresh(request)
        return request

    @staticmethod
    def execute(db: Session, request: ResponseRequest, executor_id: str) -> ResponseRequest:
        if request.status != ResponseStatus.APPROVED:
            raise ValueError("Only approved response requests can be executed")

        execution_result = FirewallConnector.execute(db, request, executor_id)
        request.status = ResponseStatus.EXECUTED
        request.executed_at = datetime.utcnow()
        request.updated_at = datetime.utcnow()
        request.execution_result = execution_result
        db.commit()
        db.refresh(request)
        return request

    @staticmethod
    def list_for_incident(db: Session, incident_id: str) -> List[ResponseRequest]:
        return (
            db.query(ResponseRequest)
            .filter(ResponseRequest.incident_id == incident_id)
            .order_by(ResponseRequest.created_at.desc())
            .all()
        )

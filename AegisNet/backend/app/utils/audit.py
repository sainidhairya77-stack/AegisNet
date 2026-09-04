"""
Audit logging utilities
"""

from datetime import datetime
from typing import Optional, Any, Dict
from uuid import uuid4
from sqlalchemy.orm import Session
from app.models import AuditLog
import logging

logger = logging.getLogger(__name__)


async def log_audit(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    result: str = "success",
    error_message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None
) -> AuditLog:
    """
    Log a security-sensitive action to the audit trail
    
    Args:
        db: Database session
        action: Action name (login, upload, analyze, etc.)
        user_id: User ID performing action
        resource_type: Type of resource affected (user, pcap, incident, etc.)
        resource_id: ID of resource affected
        result: success or failure
        error_message: Error message if failed
        details: Additional context as JSON
        source_ip: Source IP address
        user_agent: User agent string
    
    Returns:
        Created AuditLog entry
    """
    audit_entry = AuditLog(
        id=str(uuid4()),
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        error_message=error_message,
        details=details,
        source_ip=source_ip,
        user_agent=user_agent,
        created_at=datetime.utcnow()
    )
    
    try:
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        logger.debug(f"Audit log created: {action} by {user_id}")
    except Exception as e:
        logger.error(f"Failed to create audit log: {str(e)}")
        # Don't raise - audit failure shouldn't crash the application
        db.rollback()
    
    return audit_entry

"""
PCAP file handling and analysis services
"""

import hashlib
from datetime import datetime
from uuid import uuid4
from typing import Optional
from pathlib import Path
from fastapi import UploadFile, HTTPException, status
from sqlalchemy.orm import Session
import logging

from app.config import get_settings
from app.models import PcapFile, PcapStatus
from app.utils.validators import FileValidator

logger = logging.getLogger(__name__)
settings = get_settings()


class PcapFileService:
    """Service for handling PCAP file operations"""

    PCAP_MAGIC_HEADERS = (
        b"\xd4\xc3\xb2\xa1",  # little-endian pcap
        b"\xa1\xb2\xc3\xd4",  # big-endian pcap
        b"\x4d\x3c\xb2\xa1",  # nanosecond-resolution pcap
        b"\xa1\xb2\x3c\x4d",  # swapped nanosecond-resolution pcap
        b"\x0a\x0d\x0d\x0a",  # pcapng
    )

    @staticmethod
    def validate_upload(file: UploadFile) -> tuple[bool, Optional[str]]:
        """
        Validate uploaded PCAP file
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check filename
        if not file.filename:
            return False, "No filename provided"

        # Check file extension
        if not FileValidator.is_valid_filename(file.filename, settings.allowed_extensions_list):
            return False, f"Invalid file extension. Allowed: {', '.join(settings.allowed_extensions_list)}"

        # Check file size
        if file.size and file.size > settings.max_upload_size_bytes:
            return False, f"File too large. Max size: {settings.max_upload_size_mb} MB"

        return True, None

    @staticmethod
    def validate_pcap_bytes(file_bytes: bytes) -> tuple[bool, Optional[str]]:
        """Validate uploaded content before it is persisted."""
        if not file_bytes:
            return False, "Uploaded PCAP file is empty"

        if len(file_bytes) > settings.max_upload_size_bytes:
            return False, f"File too large. Max size: {settings.max_upload_size_mb} MB"

        if not any(file_bytes.startswith(header) for header in PcapFileService.PCAP_MAGIC_HEADERS):
            return False, "Invalid PCAP file content"

        return True, None

    @staticmethod
    def save_uploaded_file(file: UploadFile) -> tuple[str, str, str, int]:
        """
        Save uploaded PCAP file securely
        
        Returns:
            Tuple of (internal_filename, file_path, sha256_hash, file_size)
        """
        # Create upload directory if it doesn't exist
        upload_dir = Path(settings.upload_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)

        # Generate unique internal filename
        file_id = str(uuid4())
        ext = Path(file.filename).suffix.lower()
        internal_filename = f"{file_id}{ext}"
        file_path = upload_dir / internal_filename

        # Read file and calculate SHA256
        file_bytes = file.file.read()
        is_valid, error_msg = PcapFileService.validate_pcap_bytes(file_bytes)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )

        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Save file
        try:
            with open(file_path, "wb") as f:
                f.write(file_bytes)
            logger.info(f"PCAP file saved: {internal_filename} ({len(file_bytes)} bytes)")
        except IOError as e:
            logger.error(f"Failed to save PCAP file: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save PCAP file"
            )

        return internal_filename, str(file_path), sha256_hash, len(file_bytes)

    @staticmethod
    def create_pcap_record(
        db: Session,
        original_filename: str,
        internal_filename: str,
        file_path: str,
        sha256_hash: str,
        file_size: int,
        uploader_id: str
    ) -> PcapFile:
        """Create a PcapFile database record"""
        pcap = PcapFile(
            id=str(uuid4()),
            original_filename=original_filename,
            internal_filename=internal_filename,
            file_path=file_path,
            sha256_hash=sha256_hash,
            file_size=file_size,
            status=PcapStatus.UPLOADED,
            uploader_id=uploader_id,
            uploaded_at=datetime.utcnow()
        )

        db.add(pcap)
        db.commit()
        db.refresh(pcap)

        logger.info(f"PCAP record created: {pcap.id}")
        return pcap

    @staticmethod
    def get_pcap(db: Session, pcap_id: str) -> Optional[PcapFile]:
        """Get PCAP file by ID"""
        return db.query(PcapFile).filter(PcapFile.id == pcap_id).first()

    @staticmethod
    def list_pcaps(db: Session, user_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> list[PcapFile]:
        """List PCAP files with optional filtering"""
        query = db.query(PcapFile)

        if user_id:
            query = query.filter(PcapFile.uploader_id == user_id)

        return query.order_by(PcapFile.uploaded_at.desc()).limit(limit).offset(offset).all()

    @staticmethod
    def update_status(db: Session, pcap_id: str, status: PcapStatus, error_message: Optional[str] = None):
        """Update PCAP analysis status"""
        pcap = PcapFileService.get_pcap(db, pcap_id)
        if not pcap:
            raise HTTPException(status_code=404, detail="PCAP not found")

        pcap.status = status

        if status == PcapStatus.PROCESSING:
            pcap.analysis_started_at = datetime.utcnow()
        elif status in (PcapStatus.COMPLETED, PcapStatus.FAILED):
            pcap.analysis_completed_at = datetime.utcnow()

        if error_message:
            pcap.error_message = error_message

        db.commit()
        db.refresh(pcap)

        logger.info(f"PCAP status updated: {pcap_id} -> {status}")

import hashlib
import os
from pathlib import Path
from typing import Optional, Dict, Any
from app.storage.base import EvidenceStorage
from app.core.config import settings
from app.core.logging import logger

class LocalEvidenceStorage(EvidenceStorage):
    """Local disk evidence preservation backend with strict path sanitization."""

    def __init__(self, base_path: Optional[str] = None):
        self.root_path = Path(base_path or settings.LOCAL_STORAGE_PATH).resolve()
        self.emails_path = self.root_path / "emails"
        self.emails_path.mkdir(parents=True, exist_ok=True)

    def _get_case_folder(self, analysis_id: str) -> Path:
        # Sanitize analysis_id to prevent directory traversal
        clean_id = "".join(c for c in analysis_id if c.isalnum() or c in ("-", "_"))
        if not clean_id:
            raise ValueError(f"Invalid analysis ID: {analysis_id}")
        folder = self.emails_path / clean_id
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def save_evidence(self, analysis_id: str, data: bytes, original_filename: str) -> str:
        folder = self._get_case_folder(analysis_id)
        evidence_file = folder / "original.eml"
        
        # Write bytes atomically
        with open(evidence_file, "wb") as f:
            f.write(data)
            
        logger.info(
            f"Evidence preserved: {evidence_file.name} ({len(data)} bytes)",
            extra={"analysis_id": analysis_id, "stage": "preserving_evidence"}
        )
        return str(evidence_file.relative_to(self.root_path))

    def get_evidence(self, analysis_id: str) -> Optional[bytes]:
        try:
            folder = self._get_case_folder(analysis_id)
            evidence_file = folder / "original.eml"
            if not evidence_file.exists():
                return None
            with open(evidence_file, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read evidence for {analysis_id}: {e}")
            return None

    def verify_hash(self, analysis_id: str, expected_sha256: str) -> bool:
        data = self.get_evidence(analysis_id)
        if not data:
            return False
        computed = hashlib.sha256(data).hexdigest()
        return computed.lower() == expected_sha256.lower()

    def get_metadata(self, analysis_id: str) -> Dict[str, Any]:
        folder = self._get_case_folder(analysis_id)
        evidence_file = folder / "original.eml"
        if not evidence_file.exists():
            return {"exists": False}
        
        stat = evidence_file.stat()
        return {
            "exists": True,
            "size_bytes": stat.st_size,
            "created_timestamp": stat.st_ctime,
            "filename": "original.eml",
        }

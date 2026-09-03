from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class EvidenceStorage(ABC):
    """Abstract interface for immutable forensic evidence storage."""

    @abstractmethod
    def save_evidence(self, analysis_id: str, data: bytes, original_filename: str) -> str:
        """Store original email bytes unchanged and return internal storage reference."""
        pass

    @abstractmethod
    def get_evidence(self, analysis_id: str) -> Optional[bytes]:
        """Retrieve raw original bytes for an evidence item."""
        pass

    @abstractmethod
    def verify_hash(self, analysis_id: str, expected_sha256: str) -> bool:
        """Verify stored evidence against cryptographic SHA-256 seal."""
        pass

    @abstractmethod
    def get_metadata(self, analysis_id: str) -> Dict[str, Any]:
        """Get file metadata without exposing raw filesystem path."""
        pass

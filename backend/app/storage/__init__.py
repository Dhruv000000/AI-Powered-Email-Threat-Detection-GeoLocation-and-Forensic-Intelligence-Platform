from app.storage.base import EvidenceStorage
from app.storage.local import LocalEvidenceStorage

def get_evidence_storage() -> EvidenceStorage:
    return LocalEvidenceStorage()

__all__ = ["EvidenceStorage", "LocalEvidenceStorage", "get_evidence_storage"]

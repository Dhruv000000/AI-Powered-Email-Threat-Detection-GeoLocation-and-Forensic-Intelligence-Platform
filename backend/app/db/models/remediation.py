from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from sqlalchemy import String, DateTime, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.investigation import Investigation


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    return str(uuid4())


class RemediationExecutionLog(Base):
    """
    Audit log record for automated or manual SOC remediation actions executed against
    perimeter firewalls, mail security gateways, mailboxes, and EDR agents.
    """
    __tablename__ = "remediation_execution_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True, nullable=False
    )

    action_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_system: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="SUCCESS", index=True)  # PENDING, RUNNING, SUCCESS, FAILED, REVERTED
    
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    action_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    execution_result: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    rollback_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)

    executed_by: Mapped[str] = mapped_column(String(64), default="usr-analyst-001")
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, index=True)
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="remediation_logs")

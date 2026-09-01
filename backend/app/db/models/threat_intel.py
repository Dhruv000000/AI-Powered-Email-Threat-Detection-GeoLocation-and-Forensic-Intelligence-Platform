from datetime import datetime, timezone, timedelta
from uuid import uuid4
from typing import Optional, Dict, Any
from sqlalchemy import String, Integer, DateTime, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    return str(uuid4())


class ThreatIntelCache(Base):
    """
    Cached external threat intelligence reputation records (VirusTotal, AbuseIPDB, AlienVault OTX)
    with 24-hour time-to-live (TTL) to minimize external API rate limits.
    """
    __tablename__ = "threat_intel_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # ip, domain, url, hash, email
    indicator_value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # virustotal, abuseipdb, alienvault_otx, aggregated

    verdict: Mapped[str] = mapped_column(String(32), default="UNKNOWN")  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    reputation_score: Mapped[int] = mapped_column(Integer, default=0)  # 0 to 100
    raw_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (
        Index("ix_threat_intel_lookup", "indicator_type", "indicator_value", "provider"),
    )

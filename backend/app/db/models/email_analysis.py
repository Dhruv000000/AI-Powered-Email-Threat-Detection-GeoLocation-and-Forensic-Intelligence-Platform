import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    Index,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EmailAnalysisModel(Base):
    __tablename__ = "email_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    
    # Processing state & Progress
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True) # queued, processing, completed, failed
    stage: Mapped[str] = mapped_column(String(64), default="validating")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Classification & Risk
    threat_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    attachment_assessment: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    
    # Forensic Metadata
    model_name: Mapped[str] = mapped_column(String(64), default="aegis_email_classifier")
    model_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    feature_schema_version: Mapped[str] = mapped_column(String(32), default="1.0")
    analysis_engine_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    feature_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    score_components: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Probable Origin Candidate
    probable_origin_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    probable_origin_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    probable_origin_source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Performance Timings
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    processing_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now)

    # Relational Child Models
    metadata_record: Mapped[Optional["EmailMetadataModel"]] = relationship(
        "EmailMetadataModel", back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    headers: Mapped[List["EmailHeaderModel"]] = relationship(
        "EmailHeaderModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    relay_hops: Mapped[List["EmailRelayHopModel"]] = relationship(
        "EmailRelayHopModel", back_populates="analysis", cascade="all, delete-orphan", order_by="EmailRelayHopModel.hop_number"
    )
    authentication: Mapped[Optional["EmailAuthenticationModel"]] = relationship(
        "EmailAuthenticationModel", back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    urls: Mapped[List["EmailUrlModel"]] = relationship(
        "EmailUrlModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    ips: Mapped[List["EmailIpModel"]] = relationship(
        "EmailIpModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    attachments: Mapped[List["EmailAttachmentModel"]] = relationship(
        "EmailAttachmentModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    indicators: Mapped[List["EmailIndicatorModel"]] = relationship(
        "EmailIndicatorModel", back_populates="analysis", cascade="all, delete-orphan"
    )
    reasons: Mapped[List["AnalysisReasonModel"]] = relationship(
        "AnalysisReasonModel", back_populates="analysis", cascade="all, delete-orphan"
    )


class EmailMetadataModel(Base):
    __tablename__ = "email_metadata"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    from_header: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    from_display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    from_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    from_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    
    to_recipients: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    cc_recipients: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    bcc_recipients: Mapped[Optional[list]] = mapped_column(JSON, default=list)

    reply_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    return_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    date_header: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    body_plain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html_stripped: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="metadata_record")


class EmailHeaderModel(Base):
    __tablename__ = "email_headers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    header_name: Mapped[str] = mapped_column(String(128), nullable=False)
    header_value: Mapped[str] = mapped_column(Text, nullable=False)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="headers")


class EmailRelayHopModel(Base):
    __tablename__ = "email_relay_hops"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    hop_number: Mapped[int] = mapped_column(Integer, nullable=False)
    from_server: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    by_server: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    is_private_ip: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    delay_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_origin_node: Mapped[bool] = mapped_column(Boolean, default=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_header: Mapped[str] = mapped_column(Text, nullable=False)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="relay_hops")


class EmailAuthenticationModel(Base):
    __tablename__ = "email_authentication"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    spf_status: Mapped[str] = mapped_column(String(32), default="unknown") # pass, fail, softfail, neutral, none, temperror, permerror, unknown
    spf_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    dkim_status: Mapped[str] = mapped_column(String(32), default="unknown") # pass, fail, neutral, none, temperror, permerror, unknown
    dkim_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    dmarc_status: Mapped[str] = mapped_column(String(32), default="unknown") # pass, fail, none, unknown
    dmarc_policy: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dmarc_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="authentication")


class EmailUrlModel(Base):
    __tablename__ = "email_urls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), default="http")
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    query: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    is_ip_based: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shortened: Mapped[bool] = mapped_column(Boolean, default=False)
    is_lookalike: Mapped[bool] = mapped_column(Boolean, default=False)
    is_punycode: Mapped[bool] = mapped_column(Boolean, default=False)
    has_redirect: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    threat_level: Mapped[str] = mapped_column(String(32), default="clean")
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_location: Mapped[str] = mapped_column(String(64), default="body")

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="urls")


class EmailIpModel(Base):
    __tablename__ = "email_ips"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ip_version: Mapped[int] = mapped_column(Integer, default=4)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(64), default="received_header")
    source_location: Mapped[str] = mapped_column(String(64), default="Received")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    is_probable_origin: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="ips")


class EmailAttachmentModel(Base):
    __tablename__ = "email_attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    content_disposition: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    
    is_double_extension: Mapped[bool] = mapped_column(Boolean, default=False)
    is_executable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    detected_signals: Mapped[Optional[list]] = mapped_column(JSON, default=list)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="attachments")


class EmailIndicatorModel(Base):
    __tablename__ = "email_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True) # email, domain, url, ip, attachment_hash
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_location: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    indicator_metadata: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="indicators")


class AnalysisReasonModel(Base):
    __tablename__ = "analysis_reasons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_id: Mapped[str] = mapped_column(String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True)

    reason_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    weight: Mapped[Optional[int]] = mapped_column(Integer, default=50)

    analysis: Mapped["EmailAnalysisModel"] = relationship("EmailAnalysisModel", back_populates="reasons")

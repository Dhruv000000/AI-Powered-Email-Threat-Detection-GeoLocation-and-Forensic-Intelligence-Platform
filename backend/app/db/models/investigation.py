import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    String,
    Integer,
    Float,
    Text,
    DateTime,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationModel(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("email_analyses.analysis_id", ondelete="CASCADE"), index=True, nullable=False
    )

    # Status: created, processing, completed, failed
    status: Mapped[str] = mapped_column(String(32), default="created", index=True)
    # Lifecycle stages: loading_analysis, building_entities, building_relationships,
    # syncing_graph, generating_findings, generating_paths, generating_summary, completed
    stage: Mapped[str] = mapped_column(String(64), default="loading_analysis")
    progress: Mapped[int] = mapped_column(Integer, default=0)

    # Threat Intelligence & Authoritative Task 01 Metrics
    threat_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    investigation_confidence: Mapped[Optional[float]] = mapped_column(Float, default=0.0)

    # Safe Error Tracking
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message_safe: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Summary & Metrics Cache
    summary_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    metrics_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Ownership & Audit
    created_by: Mapped[str] = mapped_column(String(64), default="usr-analyst-001")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    analysis: Mapped["EmailAnalysisModel"] = relationship(  # noqa: F821
        "EmailAnalysisModel", foreign_keys=[analysis_id], lazy="joined"
    )
    findings: Mapped[List["InvestigationFindingModel"]] = relationship(
        "InvestigationFindingModel", back_populates="investigation", cascade="all, delete-orphan", order_by="InvestigationFindingModel.created_at"
    )
    entity_refs: Mapped[List["InvestigationEntityRefModel"]] = relationship(
        "InvestigationEntityRefModel", back_populates="investigation", cascade="all, delete-orphan"
    )
    relationship_refs: Mapped[List["InvestigationRelationshipRefModel"]] = relationship(
        "InvestigationRelationshipRefModel", back_populates="investigation", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["InvestigationAuditLogModel"]] = relationship(
        "InvestigationAuditLogModel", back_populates="investigation", cascade="all, delete-orphan", order_by="InvestigationAuditLogModel.timestamp"
    )


class InvestigationFindingModel(Base):
    __tablename__ = "investigation_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True, nullable=False
    )

    finding_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium")  # low, moderate, medium, high, critical
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.8)

    # Provenance & Traceability
    evidence_references: Mapped[List[str]] = mapped_column(JSON, default=list)
    entity_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    relationship_ids: Mapped[List[str]] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)

    investigation: Mapped["InvestigationModel"] = relationship("InvestigationModel", back_populates="findings")


class InvestigationEntityRefModel(Base):
    __tablename__ = "investigation_entity_refs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True, nullable=False
    )

    entity_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    display_label: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)

    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    evidence_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    properties: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)

    investigation: Mapped["InvestigationModel"] = relationship("InvestigationModel", back_populates="entity_refs")


class InvestigationRelationshipRefModel(Base):
    __tablename__ = "investigation_relationship_refs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True, nullable=False
    )

    relationship_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)

    provenance_source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    properties: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now)

    investigation: Mapped["InvestigationModel"] = relationship("InvestigationModel", back_populates="relationship_refs")


class InvestigationAuditLogModel(Base):
    __tablename__ = "investigation_audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True, nullable=False
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # investigation_created, investigation_viewed, finding_viewed, entity_viewed, graph_viewed, path_viewed
    entity_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=get_utc_now, index=True)

    investigation: Mapped["InvestigationModel"] = relationship("InvestigationModel", back_populates="audit_logs")

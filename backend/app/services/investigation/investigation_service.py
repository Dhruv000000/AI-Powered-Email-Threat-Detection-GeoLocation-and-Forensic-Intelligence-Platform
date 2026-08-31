from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models.investigation import (
    InvestigationModel,
    InvestigationFindingModel,
    InvestigationEntityRefModel,
    InvestigationRelationshipRefModel,
    InvestigationAuditLogModel,
)
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.investigation import (
    InvestigationDetailResponse,
    InvestigationListItemResponse,
    InvestigationFindingDTO,
    InvestigationSummaryDTO,
)


class InvestigationService:
    """
    Database service handling CRUD and relational persistence for investigations,
    findings, entity refs, relationship refs, and audit trail logs.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_by_investigation_id(self, investigation_id: str) -> Optional[InvestigationModel]:
        stmt = select(InvestigationModel).where(InvestigationModel.investigation_id == investigation_id)
        return self.db.execute(stmt).scalars().first()

    def get_by_analysis_id(self, analysis_id: str) -> Optional[InvestigationModel]:
        stmt = select(InvestigationModel).where(InvestigationModel.analysis_id == analysis_id)
        return self.db.execute(stmt).scalars().first()

    def list_investigations(
        self,
        status: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[InvestigationListItemResponse], int]:
        query = select(InvestigationModel)
        if status:
            query = query.where(InvestigationModel.status == status)
        if threat_type:
            query = query.where(InvestigationModel.threat_type == threat_type)
        if severity:
            query = query.where(InvestigationModel.severity == severity)

        total = len(self.db.execute(query).scalars().all())
        paged_query = query.order_by(desc(InvestigationModel.created_at)).offset(offset).limit(limit)
        records = self.db.execute(paged_query).scalars().all()

        items = []
        for rec in records:
            items.append(
                InvestigationListItemResponse(
                    investigation_id=rec.investigation_id,
                    analysis_id=rec.analysis_id,
                    status=rec.status,
                    threat_type=rec.threat_type,
                    risk_score=rec.risk_score,
                    severity=rec.severity,
                    created_by=rec.created_by,
                    created_at=rec.created_at,
                    completed_at=rec.completed_at,
                    finding_count=len(rec.findings) if rec.findings else 0,
                    entity_count=len(rec.entity_refs) if rec.entity_refs else 0,
                )
            )
        return items, total

    def create_investigation_record(
        self,
        analysis_id: str,
        investigation_id: str,
        created_by: str = "usr-analyst-001",
    ) -> InvestigationModel:
        record = InvestigationModel(
            investigation_id=investigation_id,
            analysis_id=analysis_id,
            status="created",
            stage="loading_analysis",
            progress=5,
            created_by=created_by,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)

        self.log_audit_event(
            investigation_id=investigation_id,
            user_id=created_by,
            action="investigation_created",
            details={"analysis_id": analysis_id},
        )
        return record

    def update_stage(
        self,
        investigation: InvestigationModel,
        stage: str,
        progress: int,
        status: str = "processing",
    ) -> None:
        investigation.stage = stage
        investigation.progress = progress
        investigation.status = status
        investigation.updated_at = datetime.now(timezone.utc)
        self.db.commit()

    def mark_failed(
        self,
        investigation: InvestigationModel,
        error_code: str,
        error_message_safe: str,
    ) -> None:
        investigation.status = "failed"
        investigation.error_code = error_code
        investigation.error_message_safe = error_message_safe
        investigation.progress = 100
        investigation.updated_at = datetime.now(timezone.utc)
        self.db.commit()

    def persist_investigation_results(
        self,
        investigation: InvestigationModel,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        summary_dict: Dict[str, Any],
    ) -> None:
        # 1. Clear old refs if re-investigating
        self.db.query(InvestigationFindingModel).filter(InvestigationFindingModel.investigation_id == investigation.investigation_id).delete()
        self.db.query(InvestigationEntityRefModel).filter(InvestigationEntityRefModel.investigation_id == investigation.investigation_id).delete()
        self.db.query(InvestigationRelationshipRefModel).filter(InvestigationRelationshipRefModel.investigation_id == investigation.investigation_id).delete()

        # 2. Persist Entity Refs
        for e in entities:
            ent_ref = InvestigationEntityRefModel(
                investigation_id=investigation.investigation_id,
                entity_id=e["id"],
                entity_type=e.get("type", "Entity"),
                display_label=e.get("display_label") or e.get("label") or e["id"],
                normalized_value=e.get("normalized_value", ""),
                risk_score=e.get("risk_score"),
                severity=e.get("severity"),
                evidence_reference=e.get("evidence_reference"),
                properties=e.get("properties", {}),
            )
            self.db.add(ent_ref)

        # 3. Persist Relationship Refs
        for r in relationships:
            rel_ref = InvestigationRelationshipRefModel(
                investigation_id=investigation.investigation_id,
                relationship_id=r["id"],
                relationship_type=r.get("type", "RELATION"),
                source_entity_id=r["source_id"],
                target_entity_id=r["target_id"],
                provenance_source=r.get("provenance", "forensic_rule"),
                source_reference=r.get("source_reference"),
                confidence=r.get("confidence", 1.0),
                properties=r.get("properties", {}),
            )
            self.db.add(rel_ref)

        # 4. Persist Findings
        for f in findings:
            fnd_rec = InvestigationFindingModel(
                investigation_id=investigation.investigation_id,
                finding_id=f["finding_id"],
                reason_code=f["reason_code"],
                title=f["title"],
                severity=f.get("severity", "medium"),
                description=f["description"],
                confidence=f.get("confidence", 0.8),
                evidence_references=f.get("evidence_references", []),
                entity_ids=f.get("entity_ids", []),
                relationship_ids=f.get("relationship_ids", []),
            )
            self.db.add(fnd_rec)

        # 5. Update Investigation Model
        investigation.status = "completed"
        investigation.stage = "completed"
        investigation.progress = 100
        investigation.threat_type = summary_dict.get("threat_type")
        investigation.risk_score = summary_dict.get("risk_score")
        investigation.severity = summary_dict.get("severity")
        investigation.ai_confidence = summary_dict.get("ai_confidence")
        investigation.investigation_confidence = summary_dict.get("investigation_confidence", 0.0)
        investigation.summary_json = summary_dict
        investigation.completed_at = datetime.now(timezone.utc)
        investigation.updated_at = datetime.now(timezone.utc)

        self.db.commit()
        self.db.refresh(investigation)

    def log_audit_event(
        self,
        investigation_id: str,
        user_id: str,
        action: str,
        entity_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            audit = InvestigationAuditLogModel(
                investigation_id=investigation_id,
                user_id=user_id,
                action=action,
                entity_id=entity_id,
                details=details or {},
            )
            self.db.add(audit)
            self.db.commit()
        except Exception:
            self.db.rollback()

    def build_detail_dto(self, record: InvestigationModel) -> InvestigationDetailResponse:
        findings_dtos = [
            InvestigationFindingDTO.model_validate(f) for f in (record.findings or [])
        ]
        summary_dto = None
        if record.summary_json:
            summary_dto = InvestigationSummaryDTO(
                investigation_id=record.investigation_id,
                analysis_id=record.analysis_id,
                threat_type=record.threat_type,
                risk_score=record.risk_score,
                severity=record.severity,
                ai_confidence=record.ai_confidence,
                investigation_confidence=record.investigation_confidence or 0.0,
                entity_counts=record.summary_json.get("entity_counts", {}),
                finding_counts=record.summary_json.get("finding_counts", {}),
                top_findings=findings_dtos[:5],
                key_threat_paths=record.summary_json.get("key_threat_paths", []),
                timeline=record.summary_json.get("timeline", []),
                executive_summary=record.summary_json.get("executive_summary"),
            )

        return InvestigationDetailResponse(
            investigation_id=record.investigation_id,
            analysis_id=record.analysis_id,
            status=record.status,
            stage=record.stage,
            progress=record.progress,
            threat_type=record.threat_type,
            risk_score=record.risk_score,
            severity=record.severity,
            ai_confidence=record.ai_confidence,
            investigation_confidence=record.investigation_confidence,
            created_by=record.created_by,
            created_at=record.created_at,
            updated_at=record.updated_at,
            completed_at=record.completed_at,
            error_code=record.error_code,
            error_message_safe=record.error_message_safe,
            summary=summary_dto,
            entity_count=len(record.entity_refs) if record.entity_refs else 0,
            relationship_count=len(record.relationship_refs) if record.relationship_refs else 0,
            finding_count=len(record.findings) if record.findings else 0,
        )

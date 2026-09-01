import hashlib
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.logging import logger
from app.db.models.email_analysis import EmailAnalysisModel
from app.db.models.investigation import InvestigationModel
from app.graph.base import GraphStore
from app.graph import get_graph_store
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.findings import FindingsEngine
from app.services.investigation.paths_engine import ThreatPathEngine
from app.services.investigation.summary_generator import SummaryEngine
from app.services.investigation.graph_service import GraphService
from app.services.investigation.investigation_service import InvestigationService
from app.schemas.investigation import InvestigationDetailResponse, InvestigationResponse


class InvestigationOrchestrator:
    """
    Investigation Orchestrator.
    Executes the 8-stage investigation pipeline:
    1. loading_analysis
    2. building_entities
    3. building_relationships
    4. syncing_graph
    5. generating_findings
    6. generating_paths
    7. generating_summary
    8. completed

    Provides unified execution for both synchronous requests and async Redis workers.
    Strictly adheres to idempotency, graph isolation, and controlled error resilience.
    """

    def __init__(self, db: Session, graph_store: Optional[GraphStore] = None):
        self.db = db
        self.store = graph_store or get_graph_store()
        self.graph_service = GraphService(self.store)
        self.inv_service = InvestigationService(db)

    def _generate_investigation_id(self, analysis_id: str) -> str:
        # Deterministic investigation ID based on analysis_id
        hash_suffix = hashlib.sha256(analysis_id.encode("utf-8")).hexdigest()[:6].upper()
        return f"INV-{analysis_id.replace('ANL-', '')}-{hash_suffix}"

    def run_investigation(
        self,
        analysis_id: str,
        force_reinvestigation: bool = False,
        created_by: str = "usr-analyst-001",
    ) -> InvestigationDetailResponse:
        logger.info(f"Starting investigation pipeline for analysis {analysis_id} (force={force_reinvestigation})")

        # 1. Stage: loading_analysis
        analysis = self.db.execute(
            select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
        ).scalars().first()

        if not analysis:
            raise ValueError(f"Task 01 forensic analysis record '{analysis_id}' was not found.")

        if analysis.status != "completed":
            raise ValueError(
                f"Cannot investigate analysis '{analysis_id}' with status '{analysis.status}'. "
                f"Task 01 analysis must be in 'completed' state."
            )

        investigation_id = self._generate_investigation_id(analysis_id)

        # 2. Idempotency Check
        existing_inv = self.inv_service.get_by_analysis_id(analysis_id)
        if existing_inv and not force_reinvestigation:
            if existing_inv.status == "completed":
                logger.info(f"Idempotent hit: returning existing completed investigation '{existing_inv.investigation_id}'.")
                return self.inv_service.build_detail_dto(existing_inv)

        # 3. Create or Reset Investigation Record
        if existing_inv:
            inv_record = existing_inv
            self.inv_service.update_stage(inv_record, stage="loading_analysis", progress=10, status="processing")
        else:
            inv_record = self.inv_service.create_investigation_record(
                analysis_id=analysis_id,
                investigation_id=investigation_id,
                created_by=created_by,
            )

        try:
            # 4. Stage: building_entities
            self.inv_service.update_stage(inv_record, stage="building_entities", progress=25)
            entity_builder = EntityBuilder(analysis, investigation_id)
            entities = entity_builder.build_all_entities()
            logger.info(f"Built {len(entities)} normalized entities for investigation {investigation_id}.")

            # 5. Stage: building_relationships
            self.inv_service.update_stage(inv_record, stage="building_relationships", progress=40)
            rel_builder = RelationshipBuilder(analysis, investigation_id, entities)
            relationships = rel_builder.build_all_relationships()
            logger.info(f"Built {len(relationships)} typed relationships for investigation {investigation_id}.")

            # 6. Stage: syncing_graph (Neo4j in production / InMemoryGraphStore in local/CI)
            self.inv_service.update_stage(inv_record, stage="syncing_graph", progress=55)
            try:
                self.graph_service.sync_investigation_graph(investigation_id, entities, relationships)
            except Exception as graph_err:
                logger.error(f"Graph synchronization failed for {investigation_id}: {graph_err}")
                self.inv_service.mark_failed(
                    inv_record,
                    error_code="NEO4J_UNAVAILABLE" if isinstance(graph_err, ConnectionError) else "GRAPH_SYNC_FAILED",
                    error_message_safe="Intelligence graph database synchronization failed. Investigation halted safely.",
                )
                raise graph_err

            # 7. Stage: generating_findings
            self.inv_service.update_stage(inv_record, stage="generating_findings", progress=70)
            findings_engine = FindingsEngine(analysis, investigation_id, entities, relationships)
            findings = findings_engine.generate_findings()
            logger.info(f"Generated {len(findings)} evidentiary findings for investigation {investigation_id}.")

            # 8. Stage: generating_paths
            self.inv_service.update_stage(inv_record, stage="generating_paths", progress=85)
            paths_engine = ThreatPathEngine(analysis, investigation_id, entities, relationships)
            threat_paths = paths_engine.compute_threat_paths()
            logger.info(f"Generated {len(threat_paths)} threat infrastructure paths for investigation {investigation_id}.")

            # 9. Stage: generating_summary
            self.inv_service.update_stage(inv_record, stage="generating_summary", progress=95)
            summary_engine = SummaryEngine(
                analysis=analysis,
                investigation_id=investigation_id,
                entities=entities,
                findings=findings,
                threat_paths=threat_paths,
                investigation_created_at=inv_record.created_at,
            )
            summary_dict = summary_engine.generate_summary()

            # 10. Stage: completed (Persist to PostgreSQL)
            self.inv_service.persist_investigation_results(
                investigation=inv_record,
                entities=entities,
                relationships=relationships,
                findings=findings,
                summary_dict=summary_dict,
            )
            logger.info(f"Investigation {investigation_id} completed successfully.")
            return self.inv_service.build_detail_dto(inv_record)

        except Exception as e:
            logger.error(f"Investigation processing error on {investigation_id}: {e}")
            if inv_record.status != "failed":
                self.inv_service.mark_failed(
                    inv_record,
                    error_code="INVESTIGATION_PROCESSING_FAILED",
                    error_message_safe="An error occurred while analyzing investigation evidence.",
                )
            raise e

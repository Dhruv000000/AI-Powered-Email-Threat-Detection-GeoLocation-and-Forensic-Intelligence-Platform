from typing import Optional, List, Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    Query,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.logging import logger
from app.db.session import get_db
from app.db.models.email_analysis import EmailAnalysisModel
from app.db.models.investigation import InvestigationModel
from app.schemas.auth import UserProfileSchema
from app.schemas.investigation import (
    CreateInvestigationRequest,
    InvestigationDetailResponse,
    InvestigationListItemResponse,
    InvestigationStatusResponse,
    InvestigationFindingDTO,
    CytoscapeGraphResponse,
    InvestigationEntityDetailDTO,
    RelatedEntitySummary,
    ThreatPathsResponse,
    ThreatPathDTO,
)
from app.api.deps import get_current_user, get_investigation_orchestrator
from app.services.investigation.orchestrator import InvestigationOrchestrator
from app.services.investigation.investigation_service import InvestigationService
from app.workers.investigation_worker import enqueue_investigation_job

router = APIRouter(prefix="/investigations", tags=["Email Threat Investigation Engine"])


@router.post(
    "",
    response_model=InvestigationDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Create or Trigger Threat Investigation",
    description=(
        "Consumes Task 01 structured forensic analysis records, normalizes all entities, "
        "builds provenance-rich typed relationships, synchronizes with the Neo4j graph store, "
        "evaluates evidence to generate findings and threat infrastructure paths, and returns "
        "the authoritative investigation workstation data."
    ),
)
def create_investigation(
    payload: CreateInvestigationRequest,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: InvestigationOrchestrator = Depends(get_investigation_orchestrator),
    db: Session = Depends(get_db),
):
    analysis_id = payload.analysis_id

    # 1. Validate analysis exists and is completed
    analysis = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No forensic analysis record found with ID '{analysis_id}'."},
        )

    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "ANALYSIS_NOT_READY",
                "message": f"Task 01 analysis '{analysis_id}' is currently '{analysis.status}'. Must be 'completed' before investigating.",
            },
        )

    # 2. Async Queued Mode (if requested)
    if payload.mode == "queued":
        inv_service = InvestigationService(db)
        inv_id = orchestrator._generate_investigation_id(analysis_id)
        existing = inv_service.get_by_analysis_id(analysis_id)
        if existing and not payload.force_reinvestigation:
            return inv_service.build_detail_dto(existing)

        if not existing:
            inv_record = inv_service.create_investigation_record(
                analysis_id=analysis_id,
                investigation_id=inv_id,
                created_by=current_user.id,
            )
        else:
            inv_record = existing
            inv_service.update_stage(inv_record, stage="loading_analysis", progress=5, status="processing")

        enqueued = enqueue_investigation_job(
            analysis_id=analysis_id,
            investigation_id=inv_record.investigation_id,
            force_reinvestigation=payload.force_reinvestigation,
        )
        if not enqueued:
            # Fallback to direct synchronous execution if Redis is unavailable
            logger.info("Async queue unavailable, falling back to direct synchronous investigation.")
            return orchestrator.run_investigation(
                analysis_id=analysis_id,
                force_reinvestigation=payload.force_reinvestigation,
                created_by=current_user.id,
            )

        return inv_service.build_detail_dto(inv_record)

    # 3. Direct Synchronous Mode (Default)
    try:
        result = orchestrator.run_investigation(
            analysis_id=analysis_id,
            force_reinvestigation=payload.force_reinvestigation,
            created_by=current_user.id,
        )
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_INVESTIGATION_REQUEST", "message": str(ve)},
        )
    except ConnectionError as ce:
        logger.error(f"Neo4j connection error during investigation: {ce}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "NEO4J_UNAVAILABLE", "message": "Graph database service is unreachable."},
        )
    except Exception as e:
        logger.error(f"Investigation execution error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "INVESTIGATION_FAILED", "message": "An unexpected error occurred during investigation execution."},
        )


@router.get(
    "",
    response_model=Dict[str, Any],
    summary="List Investigations",
    description="Lists all recorded threat investigations with pagination and optional status/threat filtering.",
)
def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status (created, processing, completed, failed)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    items, total = inv_service.list_investigations(
        status=status,
        threat_type=threat_type,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetailResponse,
    summary="Get Investigation Details",
    description="Retrieves the full investigation record, aggregated threat metrics, timeline, and top findings.",
)
def get_investigation_by_id(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        # Check by analysis_id fallback
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    inv_service.log_audit_event(
        investigation_id=record.investigation_id,
        user_id=current_user.id,
        action="investigation_viewed",
    )
    return inv_service.build_detail_dto(record)


@router.get(
    "/{investigation_id}/status",
    response_model=InvestigationStatusResponse,
    summary="Get Investigation Lifecycle Status",
    description="Retrieves real-time execution stage, progress percentage, and safe error codes for polling.",
)
def get_investigation_status(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    return InvestigationStatusResponse(
        investigation_id=record.investigation_id,
        analysis_id=record.analysis_id,
        status=record.status,
        stage=record.stage,
        progress=record.progress,
        error_code=record.error_code,
        error_message_safe=record.error_message_safe,
    )


@router.get(
    "/{investigation_id}/findings",
    response_model=List[InvestigationFindingDTO],
    summary="Get Investigation Findings",
    description="Retrieves all evidence-backed findings linked to related graph entities and relationships.",
)
def get_investigation_findings(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    inv_service.log_audit_event(
        investigation_id=record.investigation_id,
        user_id=current_user.id,
        action="finding_viewed",
    )

    return [InvestigationFindingDTO.model_validate(f) for f in (record.findings or [])]


@router.get(
    "/{investigation_id}/graph",
    response_model=CytoscapeGraphResponse,
    summary="Get Cytoscape Intelligence Graph",
    description="Retrieves the scoped intelligence graph for the investigation in Cytoscape.js format.",
)
def get_investigation_graph(
    investigation_id: str,
    max_nodes: int = Query(250, ge=10, le=1000),
    max_edges: int = Query(500, ge=10, le=2000),
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: InvestigationOrchestrator = Depends(get_investigation_orchestrator),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    inv_service.log_audit_event(
        investigation_id=record.investigation_id,
        user_id=current_user.id,
        action="graph_viewed",
    )

    graph_data = orchestrator.graph_service.get_investigation_graph(
        investigation_id=record.investigation_id,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    return CytoscapeGraphResponse(**graph_data)


@router.get(
    "/{investigation_id}/entities/{entity_id}",
    response_model=InvestigationEntityDetailDTO,
    summary="Get Specific Entity Details",
    description="Retrieves entity properties, associated risk signals, evidence references, and connected relationships.",
)
def get_investigation_entity(
    investigation_id: str,
    entity_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: InvestigationOrchestrator = Depends(get_investigation_orchestrator),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    # Find entity ref in PostgreSQL
    ent_ref = next((e for e in (record.entity_refs or []) if e.entity_id == entity_id), None)
    if not ent_ref:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ENTITY_NOT_FOUND", "message": f"No entity found with ID '{entity_id}' in this investigation."},
        )

    inv_service.log_audit_event(
        investigation_id=record.investigation_id,
        user_id=current_user.id,
        action="entity_viewed",
        entity_id=entity_id,
    )

    # Find connected relationships
    related = []
    for r in (record.relationship_refs or []):
        if r.source_entity_id == entity_id:
            target_ref = next((e for e in record.entity_refs if e.entity_id == r.target_entity_id), None)
            related.append(
                RelatedEntitySummary(
                    entity_id=r.target_entity_id,
                    entity_type=target_ref.entity_type if target_ref else "Entity",
                    display_label=target_ref.display_label if target_ref else r.target_entity_id,
                    relationship_type=r.relationship_type,
                    direction="outgoing",
                    confidence=r.confidence,
                )
            )
        elif r.target_entity_id == entity_id:
            source_ref = next((e for e in record.entity_refs if e.entity_id == r.source_entity_id), None)
            related.append(
                RelatedEntitySummary(
                    entity_id=r.source_entity_id,
                    entity_type=source_ref.entity_type if source_ref else "Entity",
                    display_label=source_ref.display_label if source_ref else r.source_entity_id,
                    relationship_type=r.relationship_type,
                    direction="incoming",
                    confidence=r.confidence,
                )
            )

    risk_signals = []
    if ent_ref.risk_score and ent_ref.risk_score >= 60:
        risk_signals.append(f"Elevated risk score ({ent_ref.risk_score}/100)")
    if ent_ref.properties.get("is_lookalike"):
        risk_signals.append("Lookalike domain pattern flagged")
    if ent_ref.properties.get("is_executable"):
        risk_signals.append("Executable file payload detected")

    evidence_refs = [ent_ref.evidence_reference] if ent_ref.evidence_reference else []

    return InvestigationEntityDetailDTO(
        entity_id=ent_ref.entity_id,
        investigation_id=record.investigation_id,
        entity_type=ent_ref.entity_type,
        display_label=ent_ref.display_label,
        normalized_value=ent_ref.normalized_value,
        risk_score=ent_ref.risk_score,
        severity=ent_ref.severity,
        evidence_reference=ent_ref.evidence_reference,
        properties=ent_ref.properties,
        risk_signals=risk_signals,
        related_entities=related,
        evidence_references=evidence_refs,
    )


@router.get(
    "/{investigation_id}/entities/{entity_id}/neighbors",
    response_model=CytoscapeGraphResponse,
    summary="Get Entity Neighbor Subgraph",
    description="Retrieves a focused 1-hop or 2-hop subgraph surrounding a specific entity.",
)
def get_entity_neighbors(
    investigation_id: str,
    entity_id: str,
    max_depth: int = Query(1, ge=1, le=3),
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: InvestigationOrchestrator = Depends(get_investigation_orchestrator),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    raw_neighbors = orchestrator.graph_service.get_entity_neighbors(
        entity_id=entity_id,
        investigation_id=record.investigation_id,
        max_depth=max_depth,
    )

    nodes = [
        {"group": "nodes", "data": {"id": n["id"], "label": n.get("label", n["id"]), "type": n.get("type", "Entity")}}
        for n in raw_neighbors.get("nodes", [])
    ]
    edges = [
        {"group": "edges", "data": {"id": e["id"], "source": e["source_id"] if "source_id" in e else e.get("source"), "target": e["target_id"] if "target_id" in e else e.get("target"), "label": e.get("type", "RELATION")}}
        for e in raw_neighbors.get("edges", [])
    ]

    return CytoscapeGraphResponse(
        investigation_id=record.investigation_id,
        node_count=len(nodes),
        edge_count=len(edges),
        nodes=nodes,
        edges=edges,
    )


@router.get(
    "/{investigation_id}/paths",
    response_model=ThreatPathsResponse,
    summary="Get Security Threat Paths",
    description="Retrieves discovered threat infrastructure paths (e.g. Email -> URL -> Domain -> IP).",
)
def get_investigation_paths(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: InvestigationOrchestrator = Depends(get_investigation_orchestrator),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id)
    if not record:
        record = inv_service.get_by_analysis_id(investigation_id)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"No investigation found with ID '{investigation_id}'."},
        )

    inv_service.log_audit_event(
        investigation_id=record.investigation_id,
        user_id=current_user.id,
        action="path_viewed",
    )

    cached_paths = (record.summary_json or {}).get("key_threat_paths", [])
    if not cached_paths:
        cached_paths = orchestrator.graph_service.find_threat_paths(record.investigation_id)

    path_dtos = [ThreatPathDTO.model_validate(p) for p in cached_paths]
    return ThreatPathsResponse(
        investigation_id=record.investigation_id,
        total_paths=len(path_dtos),
        paths=path_dtos,
    )

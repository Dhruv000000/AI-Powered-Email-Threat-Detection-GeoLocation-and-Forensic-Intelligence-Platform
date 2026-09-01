from typing import Optional, List, Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    Query,
    HTTPException,
    Response,
    status,
)
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

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
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.paths_engine import ThreatPathEngine
from app.services.investigation.threat_map_service import ThreatMapService
from app.schemas.geo import ThreatMapResponse
from app.schemas.report import DFIRReportDTO, IoCItemDTO
from app.services.investigation.report_service import DFIRReportService
from app.services.export.pdf_exporter import PDFReportExporter
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

    # 1. Resolve analysis_id if an investigation_id was provided
    if analysis_id.startswith("INV-"):
        inv_record = db.execute(
            select(InvestigationModel).where(InvestigationModel.investigation_id == analysis_id)
        ).scalars().first()
        if inv_record:
            analysis_id = inv_record.analysis_id

    # 2. Validate analysis exists and is completed
    analysis = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No forensic analysis record found with ID '{payload.analysis_id}'."},
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
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(InvestigationModel)
            .filter((InvestigationModel.analysis_id == analysis_id) | (InvestigationModel.investigation_id == analysis_id))
            .first()
        )
        if existing:
            inv_service = InvestigationService(db)
            return inv_service.build_detail_dto(existing)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "CONCURRENT_INVESTIGATION_RACE", "message": "Investigation is already being processed concurrently."},
        )
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
        import traceback
        tb = traceback.format_exc()
        logger.error(f"Investigation execution error: {e}\n{tb}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "INVESTIGATION_FAILED", "message": f"{str(e)}", "traceback": tb},
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

    # 1. Self-healing & Deterministic Reconstruction from authoritative EmailAnalysis
    analysis = db.execute(
        select(EmailAnalysisModel)
        .options(
            joinedload(EmailAnalysisModel.metadata_record),
            joinedload(EmailAnalysisModel.authentication),
            selectinload(EmailAnalysisModel.urls),
            selectinload(EmailAnalysisModel.ips),
            selectinload(EmailAnalysisModel.attachments),
            selectinload(EmailAnalysisModel.relay_hops),
        )
        .where(EmailAnalysisModel.analysis_id == record.analysis_id)
    ).scalars().first()

    if analysis:
        entity_builder = EntityBuilder(analysis, record.investigation_id)
        entities = entity_builder.build_all_entities()

        rel_builder = RelationshipBuilder(analysis, record.investigation_id, entities)
        relationships = rel_builder.build_all_relationships()

        nodes = []
        for ent in entities:
            display_name = ent.get("display_label") or ent.get("label") or ent["id"]
            nodes.append({
                "group": "nodes",
                "data": {
                    "id": ent["id"],
                    "label": display_name,
                    "name": ent.get("name") or display_name,
                    "type": ent.get("type", "Entity"),
                    "severity": ent.get("severity"),
                    "risk_score": ent.get("risk_score"),
                    "is_origin": ent.get("is_origin", False),
                    "is_suspicious": ent.get("is_suspicious", False),
                    "evidence_reference": ent.get("evidence_reference"),
                    "properties": ent.get("properties", {}),
                },
            })

        edges = []
        for rel in relationships:
            src = rel.get("source_id") or rel.get("source")
            tgt = rel.get("target_id") or rel.get("target")
            lbl = rel.get("type") or rel.get("label", "RELATION")
            edges.append({
                "group": "edges",
                "data": {
                    "id": rel["id"],
                    "source": src,
                    "target": tgt,
                    "label": lbl,
                    "provenance": rel.get("provenance"),
                    "source_reference": rel.get("source_reference"),
                    "confidence": float(rel.get("confidence", 1.0)),
                    "properties": rel.get("properties", {}),
                },
            })

        return CytoscapeGraphResponse(
            investigation_id=record.investigation_id,
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
        )

    # 2. Fallback to graph service
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

    # Deterministic reconstruction of threat paths from authoritative analysis
    analysis = db.execute(
        select(EmailAnalysisModel)
        .options(
            joinedload(EmailAnalysisModel.metadata_record),
            joinedload(EmailAnalysisModel.authentication),
            selectinload(EmailAnalysisModel.urls),
            selectinload(EmailAnalysisModel.ips),
            selectinload(EmailAnalysisModel.attachments),
            selectinload(EmailAnalysisModel.relay_hops),
        )
        .where(EmailAnalysisModel.analysis_id == record.analysis_id)
    ).scalars().first()

    if analysis:
        entity_builder = EntityBuilder(analysis, record.investigation_id)
        entities = entity_builder.build_all_entities()

        rel_builder = RelationshipBuilder(analysis, record.investigation_id, entities)
        relationships = rel_builder.build_all_relationships()

        paths_engine = ThreatPathEngine(analysis, record.investigation_id, entities, relationships)
        computed_paths = paths_engine.compute_threat_paths()

        path_dtos = [ThreatPathDTO.model_validate(p) for p in computed_paths]
        return ThreatPathsResponse(
            investigation_id=record.investigation_id,
            total_paths=len(path_dtos),
            paths=path_dtos,
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


@router.get(
    "/{investigation_id}/threat-map",
    response_model=ThreatMapResponse,
    summary="Get Investigation Threat Map & Relay Geo Routing",
    description="Reconstructs geographic hop-by-hop SMTP relay transit path, calculates total distance, and identifies routing anomalies.",
)
def get_investigation_threat_map(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id) or inv_service.get_by_analysis_id(investigation_id)
    if record:
        inv_service.log_audit_event(
            investigation_id=record.investigation_id,
            user_id=current_user.id,
            action="threat_map_viewed",
        )

    threat_map_service = ThreatMapService(db)
    return threat_map_service.get_investigation_threat_map(investigation_id)


@router.get(
    "/{investigation_id}/report",
    response_model=DFIRReportDTO,
    summary="Generate DFIR Executive Report",
    description="Synthesizes authoritative forensic report, MITRE ATT&CK matrix alignment, prioritized remediation checklist, and deduplicated IoC appendix.",
)
def get_investigation_report(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id) or inv_service.get_by_analysis_id(investigation_id)
    if record:
        inv_service.log_audit_event(
            investigation_id=record.investigation_id,
            user_id=current_user.id,
            action="dfir_report_generated",
        )

    report_service = DFIRReportService(db)
    return report_service.generate_dfir_report(investigation_id)


@router.get(
    "/{investigation_id}/export/pdf",
    summary="Export DFIR Executive Report as PDF",
    description="Generates a branded, multi-page forensic executive report PDF document for download.",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Returns generated PDF binary stream",
        }
    },
)
def export_investigation_pdf(
    investigation_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    inv_service = InvestigationService(db)
    record = inv_service.get_by_investigation_id(investigation_id) or inv_service.get_by_analysis_id(investigation_id)
    if record:
        inv_service.log_audit_event(
            investigation_id=record.investigation_id,
            user_id=current_user.id,
            action="pdf_report_exported",
        )

    report_service = DFIRReportService(db)
    report_dto = report_service.generate_dfir_report(investigation_id)

    pdf_exporter = PDFReportExporter(report_dto)
    pdf_bytes = pdf_exporter.generate_pdf()

    clean_id = investigation_id.replace(" ", "_")
    filename = f"AEGIS_DFIR_Report_{clean_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf",
        },
    )


@router.get(
    "/{investigation_id}/export/iocs",
    summary="Export Deduplicated IoCs (JSON/CSV)",
    description="Exports threat indicators of compromise formatted for SIEM/SOAR/EDR ingestion.",
)
def export_investigation_iocs(
    investigation_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_service = DFIRReportService(db)
    report_dto = report_service.generate_dfir_report(investigation_id)

    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Indicator Value", "Severity", "Killchain Stage", "Threat Context"])
        for ioc in report_dto.iocs:
            writer.writerow([ioc.ioc_type, ioc.value, ioc.severity, ioc.killchain_stage, ioc.threat_context])
        
        csv_data = output.getvalue()
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="AEGIS_IoCs_{investigation_id}.csv"'},
        )

    return {"investigation_id": investigation_id, "total_iocs": len(report_dto.iocs), "iocs": report_dto.iocs}

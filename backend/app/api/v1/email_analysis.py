import hashlib
from typing import Optional, Dict, Any, List
from fastapi import (
    APIRouter,
    Depends,
    UploadFile,
    File,
    Form,
    Query,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.session import get_db
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    AnalysisStatusResponse,
    RawEmailAnalysisRequest,
    EvidenceMetadataSchema,
    ThreatIndicatorSchema,
)
from app.schemas.auth import UserProfileSchema
from app.api.deps import get_current_user, get_orchestrator, get_storage
from app.services.email_analysis.orchestrator import AnalysisOrchestrator
from app.storage.base import EvidenceStorage
from app.workers.email_worker import enqueue_analysis_job

router = APIRouter(prefix="/email-analysis", tags=["Email Threat Analysis Engine"])


@router.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Uploaded .EML Email File",
    description=(
        "Ingests an untrusted RFC 822 .eml file, calculates cryptographic SHA-256 evidence hash, "
        "executes static forensic parsing, extract relay hops, authentication headers, URLs, IPs, "
        "domains, and attachments, runs ML classification, generates composite risk score and explanations, "
        "and persists results to PostgreSQL."
    ),
)
async def analyze_email_file(
    file: UploadFile = File(..., description="Uploaded RFC 822 .eml email file"),
    force_reanalysis: bool = Form(default=False, description="Bypass idempotency cache"),
    mode: str = Form(default="direct", description="Execution mode: 'direct' (synchronous) or 'queued' (async worker)"),
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    storage: EvidenceStorage = Depends(get_storage),
    db: Session = Depends(get_db),
):
    # 1. Validate file format and size
    filename = file.filename or "uploaded_email.eml"
    if not (filename.lower().endswith(".eml") or filename.lower().endswith(".msg") or filename.lower().endswith(".txt")):
        logger.warning(f"Rejected non-email file extension: {filename}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_FILE", "message": "Uploaded file must be a valid .eml or RFC-822 email format."},
        )

    try:
        raw_bytes = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded bytes: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_PAYLOAD", "message": "The uploaded file content could not be read."},
        )

    if len(raw_bytes) > settings.max_email_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "EMAIL_TOO_LARGE",
                "message": f"File size ({len(raw_bytes)/(1024*1024):.2f} MB) exceeds maximum allowed {settings.MAX_EMAIL_SIZE_MB} MB.",
            },
        )

    if len(raw_bytes.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_PAYLOAD", "message": "Uploaded email payload is empty."},
        )

    # 2. Async queued mode (if requested)
    if mode == "queued":
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        ts_str = hashlib.sha256(str(raw_bytes[:30]).encode()).hexdigest()[:6].upper()
        analysis_id = f"ANL-{ts_str}-{sha256[:6].upper()}"

        # Preserve evidence
        storage.save_evidence(analysis_id, raw_bytes, filename)

        # Create record in queued state
        rec = EmailAnalysisModel(
            analysis_id=analysis_id,
            filename=filename,
            sha256=sha256,
            file_size_bytes=len(raw_bytes),
            status="queued",
            stage="validating",
            progress=5,
        )
        db.add(rec)
        db.commit()

        # Enqueue to Redis
        enqueued = enqueue_analysis_job(analysis_id, filename)
        if not enqueued:
            # Fallback to direct synchronous execution if Redis is not running
            return orchestrator.process_email(raw_bytes, filename, analysis_id=analysis_id, force_reanalysis=force_reanalysis)

        return orchestrator.build_response_dto(rec)

    # 3. Direct Synchronous Mode (Default)
    try:
        result = orchestrator.process_email(
            raw_bytes=raw_bytes,
            filename=filename,
            force_reanalysis=force_reanalysis
        )
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_PAYLOAD", "message": str(ve)},
        )
    except Exception as e:
        logger.error(f"Analysis engine exception: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "ANALYSIS_ERROR", "message": "An error occurred while processing the forensic analysis."},
        )


@router.post(
    "/analyze-raw",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Raw RFC-822 Text Content",
    description="Analyzes pasted raw RFC-822 MIME headers and message body using the standard Python email parser.",
)
def analyze_raw_email(
    request: RawEmailAnalysisRequest,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
):
    if not request.raw_content or len(request.raw_content.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_PAYLOAD", "message": "Raw email content cannot be empty."},
        )

    raw_bytes = request.raw_content.encode("utf-8")
    
    if len(raw_bytes) > settings.max_email_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "EMAIL_TOO_LARGE",
                "message": f"Payload size exceeds maximum allowed {settings.MAX_EMAIL_SIZE_MB} MB.",
            },
        )

    try:
        result = orchestrator.process_email(
            raw_bytes=raw_bytes,
            filename=request.filename or "raw_pasted_email.eml",
            force_reanalysis=request.force_reanalysis
        )
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_EMAIL_PAYLOAD", "message": str(ve)},
        )
    except Exception as e:
        logger.error(f"Raw analysis exception: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "ANALYSIS_ERROR", "message": "Failed to analyze raw email content."},
        )


@router.get(
    "/{analysis_id}",
    response_model=EmailAnalysisResponse,
    summary="Get Complete Forensic Analysis Result",
    description="Retrieves the full structured forensic investigation result for a specific analysis ID.",
)
def get_analysis_result(
    analysis_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    db: Session = Depends(get_db),
):
    record = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis record found with ID '{analysis_id}'."},
        )

    return orchestrator.build_response_dto(record)


@router.get(
    "/{analysis_id}/status",
    response_model=AnalysisStatusResponse,
    summary="Get Background Analysis Processing Status",
    description="Polls real-time progress percentage and current forensic execution stage.",
)
def get_analysis_status(
    analysis_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis record found with ID '{analysis_id}'."},
        )

    return AnalysisStatusResponse(
        analysis_id=record.analysis_id,
        status=record.status,
        progress=record.progress,
        stage=record.stage,
        error_message=record.error_message,
    )


@router.get(
    "/{analysis_id}/indicators",
    response_model=Dict[str, List[Any]],
    summary="Get Normalized Extracted IoC Indicators",
    description="Retrieves first-class normalized indicators (IPs, Domains, URLs, Attachments) ready for future Neo4j/Threat Map consumption.",
)
def get_analysis_indicators(
    analysis_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    db: Session = Depends(get_db),
):
    record = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis record found with ID '{analysis_id}'."},
        )

    response_dto = orchestrator.build_response_dto(record)
    return response_dto.indicators


@router.get(
    "/{analysis_id}/evidence",
    response_model=EvidenceMetadataSchema,
    summary="Get Cryptographic Evidence Metadata & SHA-256 Seal",
    description="Retrieves evidentiary metadata and cryptographic SHA-256 verification reference.",
)
def get_analysis_evidence(
    analysis_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    db: Session = Depends(get_db),
):
    record = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis record found with ID '{analysis_id}'."},
        )

    response_dto = orchestrator.build_response_dto(record)
    return response_dto.evidence


@router.get(
    "/{analysis_id}/diagnostics",
    response_model=Dict[str, Any],
    summary="Get Development Analysis Diagnostics",
    description="Returns sanitized feature vector, model info, and rule engine metrics without exposing email bodies or credentials.",
)
def get_analysis_diagnostics(
    analysis_id: str,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = db.execute(
        select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
    ).scalars().first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis record found with ID '{analysis_id}'."},
        )

    return {
        "analysis_id": record.analysis_id,
        "input_sha256": record.sha256,
        "feature_hash": record.feature_hash,
        "classification": record.threat_type,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "ml_available": record.ai_confidence is not None,
        "model_confidence": record.ai_confidence,
        "model_name": record.model_name or "aegis_email_classifier",
        "model_version": record.model_version or "1.0.0",
        "feature_schema_version": record.feature_schema_version or "1.0",
        "rule_engine_version": record.analysis_engine_version or "1.0",
        "score_components": record.score_components or {},
        "rule_signals": [r.title for r in (record.reasons or [])],
    }

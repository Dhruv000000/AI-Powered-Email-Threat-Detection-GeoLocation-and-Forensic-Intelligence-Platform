import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator

class EmailMetadataSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_header: Optional[str] = None
    from_display_name: Optional[str] = None
    from_email: Optional[str] = None
    from_domain: Optional[str] = None
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    bcc: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    body_text_preview: Optional[str] = None


class HeaderItemSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    value: str


class RelayHopSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    hop_number: int
    from_server: Optional[str] = None
    by_server: Optional[str] = None
    ip: Optional[str] = None
    is_private_ip: bool = False
    timestamp: Optional[str] = None
    protocol: Optional[str] = None
    delay_seconds: Optional[int] = 0
    is_origin_node: bool = False
    is_anomaly: bool = False
    anomaly_reason: Optional[str] = None
    raw_header: str


class AuthStatusItem(BaseModel):
    status: str # pass, fail, softfail, neutral, none, temperror, permerror, unknown
    details: Optional[str] = None
    policy: Optional[str] = None


class AuthenticationResultsSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    spf: AuthStatusItem
    dkim: AuthStatusItem
    dmarc: AuthStatusItem


class ExtractedUrlSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    original_url: str
    normalized_url: str
    scheme: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    is_ip_based: bool = False
    is_shortened: bool = False
    is_lookalike: bool = False
    is_punycode: bool = False
    has_redirect: bool = False
    risk_score: int = 0
    threat_level: str = "clean"
    reason: Optional[str] = None
    source_location: str = "body"


class ExtractedIpSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    ip_version: int = 4
    is_private: bool = False
    source: str = "received_header"
    source_location: str = "Received"
    confidence: float = 0.5
    is_probable_origin: bool = False


class AttachmentMetadataSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    filename: str
    content_type: str
    content_disposition: Optional[str] = None
    size_bytes: int
    sha256: str
    is_double_extension: bool = False
    is_executable: bool = False
    is_suspicious: bool = False
    detected_signals: List[str] = Field(default_factory=list)


class ThreatIndicatorSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    type: str # email, domain, url, ip, attachment_hash
    value: str
    normalized_value: str
    source: str
    source_location: Optional[str] = None
    confidence: float = 0.8
    severity: str = "medium"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalysisReasonSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reason_code: str
    severity: str = "medium"
    title: str
    description: str
    evidence_reference: Optional[str] = None
    weight: Optional[int] = 50


class ProbableOriginSchema(BaseModel):
    ip: Optional[str] = None
    role: str = "probable_origin_candidate"
    confidence: float = 0.0
    source: Optional[str] = None
    basis: List[str] = Field(default_factory=list)


class ClassificationResultSchema(BaseModel):
    threat_type: str # business_email_compromise, phishing, malware, suspicious, benign, spam
    risk_score: int # 0 - 100
    severity: str # low, moderate, medium, high, critical
    ai_confidence: Optional[float] = None # 0.0 - 1.0 (calibrated model confidence)
    attachment_assessment: Optional[str] = "clean"
    score_components: Dict[str, Any] = Field(default_factory=dict)


class EvidenceMetadataSchema(BaseModel):
    sha256: str
    filename: str
    file_size_bytes: int
    integrity_status: str = "Verified"
    storage_path: Optional[str] = None


class ModelInfoSchema(BaseModel):
    name: str = "aegis_email_classifier"
    version: str = "1.0.0"
    model_type: str = "synthetic-data baseline"
    engine_version: str = "1.0.0"
    feature_schema_version: str = "1.0"
    rule_engine_version: str = "1.0"
    ml_available: bool = True
    feature_hash: Optional[str] = None


class TimingMetricsSchema(BaseModel):
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    processing_duration_ms: Optional[int] = None


# Status & Polling Request/Response
class AnalysisStatusResponse(BaseModel):
    analysis_id: str
    status: str # queued, processing, completed, failed
    progress: int = 0 # 0 - 100
    stage: str = "validating"
    error_message: Optional[str] = None


# Full Comprehensive Result Response DTO
class EmailAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: str
    status: str
    
    email: EmailMetadataSchema
    classification: ClassificationResultSchema
    authentication: AuthenticationResultsSchema
    relay_path: List[RelayHopSchema] = Field(default_factory=list)
    
    indicators: Dict[str, List[Any]] = Field(
        default_factory=lambda: {
            "ips": [],
            "domains": [],
            "urls": [],
            "attachments": [],
            "all_indicators": []
        }
    )
    
    probable_origin: Optional[ProbableOriginSchema] = None
    reasons: List[AnalysisReasonSchema] = Field(default_factory=list)
    model: ModelInfoSchema = Field(default_factory=ModelInfoSchema)
    evidence: EvidenceMetadataSchema
    timings: Optional[TimingMetricsSchema] = None


# Raw Ingest Request DTO
class RawEmailAnalysisRequest(BaseModel):
    raw_content: str = Field(..., description="Raw RFC 822 email headers and message content")
    filename: Optional[str] = Field(default="raw_pasted_email.eml", description="Optional reference filename")
    force_reanalysis: bool = Field(default=False, description="Bypass idempotency hash cache")
    mode: str = Field(default="direct", description="direct (sync) or queued (async via Redis)")

    @field_validator("raw_content", mode="before")
    @classmethod
    def clean_surrogates_in_raw_content(cls, v: Any) -> str:
        if isinstance(v, str):
            # Strip any surrogate characters (0xD800 - 0xDFFF)
            return re.sub(r"[\ud800-\udfff]", "", v)
        return str(v) if v is not None else ""

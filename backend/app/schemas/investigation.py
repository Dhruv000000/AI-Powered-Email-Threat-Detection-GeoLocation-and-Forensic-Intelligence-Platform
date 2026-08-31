from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class CreateInvestigationRequest(BaseModel):
    analysis_id: str = Field(..., description="Target Task 01 analysis ID to investigate", examples=["ANL-1234-5678"])
    force_reinvestigation: bool = Field(
        default=False,
        description="Force recreation of investigation graph and findings, bypassing idempotency cache"
    )
    mode: str = Field(
        default="direct",
        description="Execution mode: 'direct' (synchronous) or 'queued' (asynchronous Redis worker)"
    )


class InvestigationFilterParams(BaseModel):
    status: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Findings DTO
# ---------------------------------------------------------------------------

class InvestigationFindingDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    finding_id: str
    investigation_id: str
    reason_code: str
    title: str
    severity: str  # low, moderate, medium, high, critical
    description: str
    confidence: float
    evidence_references: List[str] = Field(default_factory=list)
    entity_ids: List[str] = Field(default_factory=list)
    relationship_ids: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Cytoscape Graph Models
# ---------------------------------------------------------------------------

class CytoscapeNodeData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    label: str
    type: str  # Email, Person, EmailAddress, Domain, URL, IP, Attachment, FileHash, MailServer
    severity: Optional[str] = None
    risk_score: Optional[int] = None
    is_origin: Optional[bool] = False
    is_suspicious: Optional[bool] = False
    evidence_reference: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class CytoscapeNode(BaseModel):
    group: str = "nodes"
    data: CytoscapeNodeData


class CytoscapeEdgeData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    target: str
    label: str  # relationship_type: SENT, LINKS_TO, USES_DOMAIN, etc.
    provenance: Optional[str] = None
    source_reference: Optional[str] = None
    confidence: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)


class CytoscapeEdge(BaseModel):
    group: str = "edges"
    data: CytoscapeEdgeData


class CytoscapeGraphResponse(BaseModel):
    investigation_id: str
    node_count: int
    edge_count: int
    nodes: List[CytoscapeNode]
    edges: List[CytoscapeEdge]


# ---------------------------------------------------------------------------
# Entity & Relationship Detail DTOs
# ---------------------------------------------------------------------------

class RelatedEntitySummary(BaseModel):
    entity_id: str
    entity_type: str
    display_label: str
    relationship_type: str
    direction: str  # 'outgoing' or 'incoming'
    confidence: float = 1.0


class InvestigationEntityDetailDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entity_id: str
    investigation_id: str
    entity_type: str
    display_label: str
    normalized_value: str
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    evidence_reference: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    risk_signals: List[str] = Field(default_factory=list)
    related_entities: List[RelatedEntitySummary] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)


class InvestigationRelationshipDetailDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    relationship_id: str
    investigation_id: str
    relationship_type: str
    source_entity_id: str
    target_entity_id: str
    source_label: Optional[str] = None
    target_label: Optional[str] = None
    provenance_source: str
    source_reference: Optional[str] = None
    confidence: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Threat Paths Models
# ---------------------------------------------------------------------------

class ThreatPathStepDTO(BaseModel):
    node_id: str
    node_label: str
    node_type: str
    relationship_type: Optional[str] = None
    target_node_id: Optional[str] = None


class ThreatPathDTO(BaseModel):
    path_id: str
    path_type: str  # credential_harvesting_path, malware_delivery_path, origin_relay_path, impersonation_path
    title: str
    description: str
    severity: str
    confidence: float
    steps: List[str]  # Human-readable step descriptions
    node_ids: List[str]
    edge_ids: List[str]


class ThreatPathsResponse(BaseModel):
    investigation_id: str
    total_paths: int
    paths: List[ThreatPathDTO]


# ---------------------------------------------------------------------------
# Timeline & Summary Models
# ---------------------------------------------------------------------------

class TimelineEventDTO(BaseModel):
    id: str
    timestamp: str
    title: str
    event_type: str  # email_received, header_observed, url_extracted, attachment_identified, analysis_completed, investigation_started, graph_generated, investigation_completed
    description: str
    source: str
    evidence_reference: Optional[str] = None


class InvestigationSummaryDTO(BaseModel):
    investigation_id: str
    analysis_id: str
    threat_type: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    ai_confidence: Optional[float] = None
    investigation_confidence: float = 0.0
    entity_counts: Dict[str, int] = Field(default_factory=dict)
    finding_counts: Dict[str, int] = Field(default_factory=dict)
    top_findings: List[InvestigationFindingDTO] = Field(default_factory=list)
    key_threat_paths: List[ThreatPathDTO] = Field(default_factory=list)
    timeline: List[TimelineEventDTO] = Field(default_factory=list)
    executive_summary: Optional[str] = None


# ---------------------------------------------------------------------------
# Status & Full Detail Response Models
# ---------------------------------------------------------------------------

class InvestigationStatusResponse(BaseModel):
    investigation_id: str
    analysis_id: str
    status: str  # created, processing, completed, failed
    stage: str  # loading_analysis, building_entities, building_relationships, syncing_graph, generating_findings, generating_paths, generating_summary, completed
    progress: int  # 0 - 100
    error_code: Optional[str] = None
    error_message_safe: Optional[str] = None


class InvestigationDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    investigation_id: str
    analysis_id: str
    status: str
    stage: str
    progress: int
    threat_type: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    ai_confidence: Optional[float] = None
    investigation_confidence: Optional[float] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    error_code: Optional[str] = None
    error_message_safe: Optional[str] = None
    summary: Optional[InvestigationSummaryDTO] = None
    entity_count: int = 0
    relationship_count: int = 0
    finding_count: int = 0


class InvestigationListItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    investigation_id: str
    analysis_id: str
    status: str
    threat_type: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    created_by: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    finding_count: int = 0
    entity_count: int = 0

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class InvestigationCreateRequest(BaseModel):
    analysis_id: str = Field(..., description="Target Task 01 analysis ID to investigate", examples=["ANL-1234-5678"])
    force_reinvestigation: bool = Field(
        default=False,
        description="Force recreation of investigation graph and findings, bypassing idempotency cache"
    )
    mode: str = Field(
        default="direct",
        description="Execution mode: 'direct' (synchronous) or 'queued' (asynchronous Redis worker)"
    )


# Backward-compatible alias
CreateInvestigationRequest = InvestigationCreateRequest


class InvestigationFilterParams(BaseModel):
    status: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Graph & Cytoscape Node / Edge Models
# ---------------------------------------------------------------------------

class GraphNodeData(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    id: str
    label: str
    name: Optional[str] = None
    type: str  # Email, Person, EmailAddress, Domain, URL, IP, Attachment, FileHash, MailServer
    risk_score: Optional[int] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    severity: Optional[str] = None
    is_origin: Optional[bool] = False
    is_suspicious: Optional[bool] = False
    evidence_reference: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if self.name is None:
            self.name = self.label


CytoscapeNodeData = GraphNodeData


class GraphNode(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    group: str = "nodes"
    data: GraphNodeData


CytoscapeNode = GraphNode


class GraphEdgeData(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    id: str
    source: str
    target: str
    label: str  # relationship_type: SENT, LINKS_TO, USES_DOMAIN, etc.
    provenance: Optional[str] = None
    source_reference: Optional[str] = None
    confidence: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)


CytoscapeEdgeData = GraphEdgeData


class GraphEdge(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    group: str = "edges"
    data: GraphEdgeData


CytoscapeEdge = GraphEdge


class CytoscapeGraphResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    investigation_id: Optional[str] = None
    node_count: int = 0
    edge_count: int = 0
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.node_count and self.nodes:
            self.node_count = len(self.nodes)
        if not self.edge_count and self.edges:
            self.edge_count = len(self.edges)


# ---------------------------------------------------------------------------
# Findings DTO
# ---------------------------------------------------------------------------

class InvestigationFindingDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    id: Optional[Any] = None
    finding_id: Optional[str] = None
    investigation_id: str
    finding_code: Optional[str] = None
    reason_code: Optional[str] = None
    title: str
    severity: str = "medium"  # low, moderate, medium, high, critical
    description: str
    confidence: float = 0.8
    evidence_json: Optional[Any] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    entity_ids: List[str] = Field(default_factory=list)
    relationship_ids: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.finding_code and self.reason_code:
            self.finding_code = self.reason_code
        elif not self.reason_code and self.finding_code:
            self.reason_code = self.finding_code
        if not self.finding_id:
            self.finding_id = self.finding_code or "FND-000"


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


class ThreatPath(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    path_id: str
    title: str
    severity: str
    description: str
    node_ids: List[str] = Field(default_factory=list)
    edge_ids: List[str] = Field(default_factory=list)
    path_type: Optional[str] = None
    confidence: Optional[float] = 1.0
    steps: List[str] = Field(default_factory=list)


# Backward-compatible alias
ThreatPathDTO = ThreatPath


class ThreatPathsResponse(BaseModel):
    investigation_id: str
    total_paths: int
    paths: List[ThreatPath]


# ---------------------------------------------------------------------------
# Timeline & Summary Models
# ---------------------------------------------------------------------------

class TimelineEventDTO(BaseModel):
    id: str
    timestamp: str
    title: str
    event_type: str
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
    key_threat_paths: List[ThreatPath] = Field(default_factory=list)
    timeline: List[TimelineEventDTO] = Field(default_factory=list)
    executive_summary: Optional[str] = None
    attachments_count: int = 0
    malicious_attachments_count: int = 0
    high_risk_links: int = 0


# ---------------------------------------------------------------------------
# Status & Full Detail Response Models
# ---------------------------------------------------------------------------

class InvestigationStatusResponse(BaseModel):
    investigation_id: str
    analysis_id: str
    status: str  # created, processing, completed, failed
    stage: str
    progress: int  # 0 - 100
    error_code: Optional[str] = None
    error_message_safe: Optional[str] = None


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    investigation_id: str
    analysis_id: str
    status: str
    node_count: int = 0
    edge_count: int = 0
    threat_path_count: int = 0
    summary: str = ""


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

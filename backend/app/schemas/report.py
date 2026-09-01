from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class MitreTechniqueDTO(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID (e.g. T1566.002)")
    name: str = Field(..., description="Technique name (e.g. Spearphishing Link)")
    tactic: str = Field(..., description="ATT&CK Tactic (e.g. Initial Access)")
    description: str
    matched_indicators: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    url: str = Field(..., description="Direct link to MITRE ATT&CK documentation")


class RemediationActionDTO(BaseModel):
    action_id: str
    priority: str = Field(..., description="Priority level: P0 (Immediate Containment), P1 (Eradication), P2 (Hardening)")
    title: str
    category: str = Field(..., description="Containment, Eradication, Hardening, or User Communication")
    description: str
    target_system: str = Field(..., description="Email Gateway, DNS/Firewall, EDR, Identity Provider, etc.")
    automated_action: Optional[str] = None


class IoCItemDTO(BaseModel):
    ioc_type: str = Field(..., description="Domain, URL, IP, EmailAddress, SHA256, FileHash")
    value: str
    threat_context: str
    severity: str = Field(default="medium", description="critical, high, medium, low, info")
    killchain_stage: str = Field(default="Initial Access")


class ExecutiveSummaryDTO(BaseModel):
    verdict: str
    classification: str
    risk_score: int
    severity: str
    ai_confidence: float
    narrative: str
    key_takeaways: List[str] = Field(default_factory=list)
    attack_vector: str
    potential_impact: str


class DFIRReportDTO(BaseModel):
    report_id: str
    investigation_id: str
    analysis_id: str
    generated_at: str
    generated_by: str = "AEGIS Automated Forensic Intelligence Engine"
    case_reference: str
    email_metadata: Dict[str, Any] = Field(default_factory=dict)
    executive_summary: ExecutiveSummaryDTO
    mitre_matrix: List[MitreTechniqueDTO] = Field(default_factory=list)
    remediation_plan: List[RemediationActionDTO] = Field(default_factory=list)
    iocs: List[IoCItemDTO] = Field(default_factory=list)
    evidentiary_findings: List[Dict[str, Any]] = Field(default_factory=list)
    forensic_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    threat_paths: List[Dict[str, Any]] = Field(default_factory=list)
    transit_route_summary: Optional[Dict[str, Any]] = None

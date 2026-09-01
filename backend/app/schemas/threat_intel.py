from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ThreatIntelLookupRequest(BaseModel):
    indicator: str = Field(..., description="Target IoC indicator string (URL, IP, Domain, SHA256, Email)")
    indicator_type: Optional[str] = Field(None, description="Optional indicator type: ip, domain, url, hash, email")
    force_refresh: bool = Field(default=False, description="If True, bypasses cache and forces external query")


class ThreatIntelProviderResultDTO(BaseModel):
    provider: str = Field(..., description="virustotal, abuseipdb, alienvault_otx, offline_mock")
    verdict: str = Field(..., description="MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN")
    score: int = Field(default=0, ge=0, le=100)
    detection_ratio: Optional[str] = Field(None, description="e.g. 58/72 engines")
    abuse_confidence: Optional[int] = Field(None, ge=0, le=100)
    pulses_count: Optional[int] = None
    malware_families: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class ThreatIntelDTO(BaseModel):
    indicator: str
    indicator_type: str
    overall_verdict: str = Field(..., description="MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN")
    overall_score: int = Field(default=0, ge=0, le=100)
    cached: bool = False
    cached_at: str
    expires_at: str
    providers: List[ThreatIntelProviderResultDTO] = Field(default_factory=list)


class ProcessTreeNodeDTO(BaseModel):
    pid: int
    parent_pid: Optional[int] = None
    process_name: str
    command_line: str
    is_suspicious: bool = False
    children: List["ProcessTreeNodeDTO"] = Field(default_factory=list)


class NetworkCallbackDTO(BaseModel):
    protocol: str = "HTTPS"
    destination: str
    port: int = 443
    behavior: str = "Outbound Beacon"
    is_threat: bool = True


class RegistryModificationDTO(BaseModel):
    key: str
    value_name: str
    action: str = "SET_VALUE"
    data: Optional[str] = None
    is_persistence: bool = True


class SandboxReportDTO(BaseModel):
    sha256: str
    md5: str
    sha1: str
    file_name: str
    file_type: str
    file_size_bytes: int = 0
    verdict: str = Field(..., description="MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN")
    risk_score: int = Field(default=0, ge=0, le=100)
    magic_bytes: str = "N/A"
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)
    structural_flags: List[str] = Field(default_factory=list)
    macro_analysis: Optional[Dict[str, Any]] = None
    pdf_analysis: Optional[Dict[str, Any]] = None
    process_tree: List[ProcessTreeNodeDTO] = Field(default_factory=list)
    network_callbacks: List[NetworkCallbackDTO] = Field(default_factory=list)
    registry_modifications: List[RegistryModificationDTO] = Field(default_factory=list)
    dropped_files: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class EnrichedInvestigationDTO(BaseModel):
    investigation_id: str
    analysis_id: str
    total_indicators: int = 0
    malicious_indicators_count: int = 0
    indicators: List[ThreatIntelDTO] = Field(default_factory=list)
    attachments: List[SandboxReportDTO] = Field(default_factory=list)
    enriched_at: str

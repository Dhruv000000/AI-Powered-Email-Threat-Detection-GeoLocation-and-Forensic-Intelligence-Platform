from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class GeoLocationDTO(BaseModel):
    ip: str
    is_private: bool = False
    is_bogon: bool = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    country: Optional[str] = None
    country_name: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    formatted_address: Optional[str] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None
    is_datacenter_or_vpn: bool = False
    is_tor: bool = False


class GeoLookupRequest(BaseModel):
    ips: List[str] = Field(..., min_length=1, max_length=100, description="List of IPv4 or IPv6 addresses to resolve")


class GeoLookupResponse(BaseModel):
    results: List[GeoLocationDTO]
    total_resolved: int


class ThreatMapHopDTO(BaseModel):
    hop_number: int
    ip: str
    hostname: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[float] = None
    location: Optional[GeoLocationDTO] = None
    is_origin: bool = False
    is_destination: bool = False
    is_target: bool = False
    role: Optional[str] = None
    is_suspicious: bool = False
    is_anomaly: bool = False
    anomaly_reason: Optional[str] = None


class ThreatMapResponse(BaseModel):
    investigation_id: str
    analysis_id: str
    origin_ip: Optional[GeoLocationDTO] = None
    destination_ip: Optional[GeoLocationDTO] = None
    hops: List[ThreatMapHopDTO] = Field(default_factory=list)
    total_distance_km: float = 0.0
    anomalies: List[str] = Field(default_factory=list)
    risk_score: Optional[int] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None

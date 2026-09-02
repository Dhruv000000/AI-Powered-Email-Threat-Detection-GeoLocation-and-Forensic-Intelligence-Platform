"""
Forensic Threat Map & Geolocation Service.
Re-exports ThreatMapService from app.services.investigation.threat_map_service.
"""
from app.services.investigation.threat_map_service import ThreatMapService

__all__ = ["ThreatMapService"]

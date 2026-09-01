"""
Backward-compatibility alias module for ThreatPathEngine.
Main implementation resides in app.services.investigation.paths_engine.
"""
from app.services.investigation.paths_engine import ThreatPathEngine

__all__ = ["ThreatPathEngine"]

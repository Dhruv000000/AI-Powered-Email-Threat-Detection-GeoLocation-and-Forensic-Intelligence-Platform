"""
Backward-compatibility alias module for SummaryEngine and summary helpers.
Main implementation resides in app.services.investigation.summary_generator.
"""
from app.services.investigation.summary_generator import (
    SummaryEngine,
    generate_investigation_summary,
)

__all__ = [
    "SummaryEngine",
    "generate_investigation_summary",
]

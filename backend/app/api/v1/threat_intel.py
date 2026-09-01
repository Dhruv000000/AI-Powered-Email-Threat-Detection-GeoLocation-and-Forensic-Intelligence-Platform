from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_user
from app.schemas.auth import UserProfileSchema
from app.schemas.threat_intel import ThreatIntelLookupRequest, ThreatIntelDTO
from app.services.threat_intel.threat_intel_service import ThreatIntelAggregator

router = APIRouter(prefix="/threat-intel", tags=["External Threat Intelligence Engine"])


@router.post(
    "/lookup",
    response_model=ThreatIntelDTO,
    status_code=status.HTTP_200_OK,
    summary="Ad-Hoc Threat Intelligence Indicator Lookup",
    description="Queries VirusTotal, AbuseIPDB, and AlienVault OTX for an indicator with 24-hour persistent caching.",
)
def lookup_indicator_threat_intel(
    payload: ThreatIntelLookupRequest,
    current_user: UserProfileSchema = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    aggregator = ThreatIntelAggregator(db)
    return aggregator.enrich_indicator(
        indicator=payload.indicator,
        indicator_type=payload.indicator_type,
        force_refresh=payload.force_refresh,
    )

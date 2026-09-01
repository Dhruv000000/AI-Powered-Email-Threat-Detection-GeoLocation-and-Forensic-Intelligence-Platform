from fastapi import APIRouter, Depends, status
from app.schemas.geo import GeoLookupRequest, GeoLookupResponse
from app.schemas.auth import UserProfileSchema
from app.api.deps import get_current_user
from app.services.geo.geo_resolver import geo_resolver

router = APIRouter(prefix="/geo", tags=["IP Geolocation & Threat Intelligence"])


@router.post(
    "/lookup",
    response_model=GeoLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch IP Geolocation & ASN Resolution",
    description="Resolves a list of IPv4/IPv6 addresses to geographic coordinates, ASNs, and Bogon flags.",
)
def lookup_ip_batch(
    payload: GeoLookupRequest,
    current_user: UserProfileSchema = Depends(get_current_user),
):
    resolved = geo_resolver.resolve_ips(payload.ips)
    return GeoLookupResponse(
        results=resolved,
        total_resolved=len(resolved),
    )

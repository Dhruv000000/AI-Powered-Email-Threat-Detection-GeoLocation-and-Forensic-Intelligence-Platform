"""
Forensic GeoIP and Autonomous System Resolver.
Re-exports GeoResolver and static DFIR telemetry tables from app.services.geo.geo_resolver.
"""
from app.services.geo.geo_resolver import (
    GeoResolver,
    geo_resolver,
    STATIC_GEO_DATABASE,
    STATIC_SUBNET_DATABASE,
    COUNTRY_COORDINATE_CENTROIDS,
)
from app.schemas.geo import GeoLocationDTO

__all__ = [
    "GeoResolver",
    "geo_resolver",
    "STATIC_GEO_DATABASE",
    "STATIC_SUBNET_DATABASE",
    "COUNTRY_COORDINATE_CENTROIDS",
    "GeoLocationDTO",
]

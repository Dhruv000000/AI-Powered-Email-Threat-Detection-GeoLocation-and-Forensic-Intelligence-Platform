from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import select
from fastapi import HTTPException, status

from app.core.logging import logger
from app.db.models.investigation import InvestigationModel
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.geo import (
    GeoLocationDTO,
    ThreatMapHopDTO,
    ThreatMapResponse,
)
from app.services.geo.geo_resolver import geo_resolver, GeoResolver


class ThreatMapService:
    """
    Forensic Threat Map & Geolocation Engine.
    Reconstructs hop-by-hop SMTP relay transit paths, computes geospatial distances,
    and identifies routing anomalies (e.g. Tor relays, impossible travel, multi-continent routing).
    """

    def __init__(self, db: Session):
        self.db = db

    def get_investigation_threat_map(self, target_id: str) -> ThreatMapResponse:
        # 1. Lookup Investigation Record if existing
        inv_record = self.db.execute(
            select(InvestigationModel).where(
                (InvestigationModel.investigation_id == target_id)
                | (InvestigationModel.analysis_id == target_id)
            )
        ).scalars().first()

        target_analysis_id = inv_record.analysis_id if inv_record else target_id

        # 2. Eagerly load authoritative EmailAnalysis record
        analysis = self.db.execute(
            select(EmailAnalysisModel)
            .options(
                joinedload(EmailAnalysisModel.metadata_record),
                joinedload(EmailAnalysisModel.authentication),
                selectinload(EmailAnalysisModel.urls),
                selectinload(EmailAnalysisModel.ips),
                selectinload(EmailAnalysisModel.attachments),
                selectinload(EmailAnalysisModel.relay_hops),
            )
            .where(EmailAnalysisModel.analysis_id == target_analysis_id)
        ).scalars().first()

        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No email analysis or investigation record found for '{target_id}'."},
            )

        # 3. Extract and order Relay Hops
        raw_hops = list(analysis.relay_hops or [])
        raw_hops.sort(key=lambda h: h.hop_number)

        hops_dto: List[ThreatMapHopDTO] = []
        anomalies: List[str] = []
        total_distance = 0.0
        prev_loc: Optional[GeoLocationDTO] = None

        import re
        if raw_hops:
            total_hops = len(raw_hops)
            for idx, hop in enumerate(raw_hops):
                raw_hdr = getattr(hop, "raw_header", "") or ""
                from_srv = getattr(hop, "from_server", None) or getattr(hop, "from_host", None) or ""
                by_srv = getattr(hop, "by_server", None) or getattr(hop, "by_host", None) or ""

                # 1. Best IP candidate
                hop_ip = (getattr(hop, "ip", None) or getattr(hop, "sender_ip", None) or "").strip()
                if not hop_ip:
                    # Try to extract IP from raw header
                    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", f"{from_srv} {raw_hdr} {by_srv}")
                    if ip_match:
                        hop_ip = ip_match.group(0)
                    else:
                        hop_ip = from_srv or by_srv or "Unknown"

                geo_dto = geo_resolver.resolve_ip(hop_ip)
                is_orig = (idx == 0) or hop.is_origin_node
                is_dest = (idx == total_hops - 1)

                is_susp = False
                if geo_dto.is_tor:
                    is_susp = True
                    tor_msg = f"Hop #{hop.hop_number} ({hop_ip}) routed through an active Tor Exit Node ({geo_dto.as_org})."
                    if tor_msg not in anomalies:
                        anomalies.append(tor_msg)
                if hop.is_anomaly:
                    is_susp = True
                    if hop.anomaly_reason and hop.anomaly_reason not in anomalies:
                        anomalies.append(f"Hop #{hop.hop_number} routing anomaly: {hop.anomaly_reason}")

                # Distance accumulation
                if prev_loc and prev_loc.latitude is not None and geo_dto.latitude is not None:
                    leg_dist = GeoResolver.calculate_haversine_distance(
                        prev_loc.latitude, prev_loc.longitude,
                        geo_dto.latitude, geo_dto.longitude
                    )
                    total_distance += leg_dist

                    # Check for impossible transit speed
                    if hop.delay_seconds is not None and hop.delay_seconds < 3 and leg_dist > 3000:
                        speed_anomaly = (
                            f"Impossible transit speed: {leg_dist:.0f} km traversed between Hop #{idx} ({prev_loc.country_name}) "
                            f"and Hop #{idx + 1} ({geo_dto.country_name}) in {hop.delay_seconds:.1f}s."
                        )
                        if speed_anomaly not in anomalies:
                            anomalies.append(speed_anomaly)

                if geo_dto.latitude is not None:
                    prev_loc = geo_dto

                hops_dto.append(
                    ThreatMapHopDTO(
                        hop_number=hop.hop_number,
                        ip=hop_ip,
                        hostname=from_srv or hop_ip,
                        by_host=by_srv,
                        protocol=hop.protocol or "ESMTP",
                        timestamp=str(hop.timestamp) if hop.timestamp else None,
                        delay_seconds=float(hop.delay_seconds) if hop.delay_seconds is not None else None,
                        location=geo_dto,
                        is_origin=is_orig,
                        is_destination=is_dest,
                        is_suspicious=is_susp,
                        is_anomaly=hop.is_anomaly or (geo_dto.is_tor),
                        anomaly_reason=hop.anomaly_reason or ("Tor Exit Node" if geo_dto.is_tor else None),
                    )
                )

        # Fallback / Augment: If no hops or all hops were private, include candidate origin IP
        geocoded_count = sum(1 for h in hops_dto if h.location and h.location.latitude is not None)
        if geocoded_count == 0:
            candidate_ip = (
                analysis.probable_origin_ip
                or (analysis.ips[0].ip if analysis.ips else None)
                or (analysis.metadata_record.from_email.split("@")[-1] if analysis.metadata_record and analysis.metadata_record.from_email else None)
            )
            if candidate_ip:
                geo_dto = geo_resolver.resolve_ip(candidate_ip)
                hops_dto.insert(
                    0,
                    ThreatMapHopDTO(
                        hop_number=1,
                        ip=candidate_ip,
                        hostname=candidate_ip,
                        protocol="SMTP",
                        location=geo_dto,
                        is_origin=True,
                        is_destination=len(hops_dto) == 0,
                        is_suspicious=geo_dto.is_tor,
                        is_anomaly=geo_dto.is_tor,
                        anomaly_reason="Tor Exit Node" if geo_dto.is_tor else None,
                    )
                )
                # Re-number hops
                for idx, h in enumerate(hops_dto, start=1):
                    h.hop_number = idx

        # 4. Resolve Origin and Destination Location objects
        origin_ip = hops_dto[0].location if hops_dto else None
        destination_ip = hops_dto[-1].location if (hops_dto and len(hops_dto) > 1) else None

        # Check for multi-national hops
        unique_countries = {h.location.country_name for h in hops_dto if h.location and h.location.country_name and not h.location.is_private}
        if len(unique_countries) >= 3:
            multi_country_msg = f"Multi-national routing path traversed across {len(unique_countries)} jurisdictions: {', '.join(sorted(unique_countries))}."
            if multi_country_msg not in anomalies:
                anomalies.append(multi_country_msg)

        inv_id_val = inv_record.investigation_id if inv_record else f"INV-{analysis.analysis_id}"
        risk_score_val = (inv_record.risk_score if inv_record else None) or analysis.risk_score
        threat_type_val = (inv_record.threat_type if inv_record else None) or analysis.threat_type

        return ThreatMapResponse(
            investigation_id=inv_id_val,
            analysis_id=analysis.analysis_id,
            origin_ip=origin_ip,
            destination_ip=destination_ip,
            hops=hops_dto,
            total_distance_km=round(total_distance, 2),
            anomalies=anomalies,
            risk_score=risk_score_val,
            threat_type=threat_type_val,
        )

import ipaddress
from typing import List, Dict, Any, Optional, Tuple, Set
from app.schemas.email_analysis import ExtractedIpSchema, RelayHopSchema, ProbableOriginSchema

class IpExtractor:
    """Forensic IP address extraction and Candidate Infrastructure Origin determination engine."""

    @classmethod
    def extract_ips(
        cls,
        relay_hops: List[RelayHopSchema],
        raw_headers: List[Tuple[str, str]],
        extracted_urls: List[Any]
    ) -> Tuple[List[ExtractedIpSchema], Optional[ProbableOriginSchema]]:
        seen_ips: Set[str] = set()
        ip_records: List[ExtractedIpSchema] = []

        # 1. Extract from Received Relay Hops
        for hop in relay_hops:
            if hop.ip and hop.ip not in seen_ips:
                seen_ips.add(hop.ip)
                try:
                    ip_obj = ipaddress.ip_address(hop.ip)
                    is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
                    version = ip_obj.version
                except ValueError:
                    is_priv = False
                    version = 4

                ip_records.append(
                    ExtractedIpSchema(
                        ip=hop.ip,
                        ip_version=version,
                        is_private=is_priv,
                        source="received_header",
                        source_location=f"Hop #{hop.hop_number} ({hop.from_server or 'relay'})",
                        confidence=0.85 if not is_priv else 0.40,
                        is_probable_origin=False,
                    )
                )

        # 2. Extract from explicit Originating Headers (X-Originating-IP, X-Sender-IP, X-Client-IP)
        origin_header_names = {"x-originating-ip", "x-sender-ip", "x-client-ip", "x-real-ip"}
        for name, val in raw_headers:
            if name.lower() in origin_header_names:
                cleaned_val = val.strip().replace("[", "").replace("]", "")
                for candidate in cleaned_val.split():
                    try:
                        ip_obj = ipaddress.ip_address(candidate.strip())
                        cand_str = str(ip_obj)
                        if cand_str not in seen_ips:
                            seen_ips.add(cand_str)
                            ip_records.append(
                                ExtractedIpSchema(
                                    ip=cand_str,
                                    ip_version=ip_obj.version,
                                    is_private=ip_obj.is_private,
                                    source="originating_header",
                                    source_location=name,
                                    confidence=0.90,
                                    is_probable_origin=False,
                                )
                            )
                    except ValueError:
                        continue

        # 3. Extract from IP-based URLs
        for url_item in extracted_urls:
            hostname = getattr(url_item, "hostname", "") or ""
            if hostname and hostname not in seen_ips:
                try:
                    ip_obj = ipaddress.ip_address(hostname)
                    cand_str = str(ip_obj)
                    seen_ips.add(cand_str)
                    ip_records.append(
                        ExtractedIpSchema(
                            ip=cand_str,
                            ip_version=ip_obj.version,
                            is_private=ip_obj.is_private,
                            source="url_host",
                            source_location="Email Body Hyperlink",
                            confidence=0.75,
                            is_probable_origin=False,
                        )
                    )
                except ValueError:
                    pass

        # 4. Determine Probable Infrastructure Origin Candidate
        # Candidate selection rule: Earliest non-private IP in the chronological relay chain
        probable_origin = None
        
        # Check explicit X-Originating-IP first if public
        for rec in ip_records:
            if rec.source == "originating_header" and not rec.is_private:
                rec.is_probable_origin = True
                probable_origin = ProbableOriginSchema(
                    ip=rec.ip,
                    role="probable_origin_candidate",
                    confidence=0.92,
                    source=rec.source_location,
                    basis=[
                        "explicit_origin_header",
                        "public_ip",
                        f"header_name_{rec.source_location}"
                    ]
                )
                break

        # If not found from X-Originating-IP, evaluate chronological relay hops (Hop 1, Hop 2, etc.)
        if not probable_origin:
            for hop in relay_hops:
                if hop.ip and not hop.is_private_ip:
                    # Mark corresponding IP record
                    for rec in ip_records:
                        if rec.ip == hop.ip:
                            rec.is_probable_origin = True
                            break

                    confidence = 0.85 if hop.hop_number == 1 else max(0.40, 0.80 - (hop.hop_number * 0.10))
                    probable_origin = ProbableOriginSchema(
                        ip=hop.ip,
                        role="probable_origin_candidate",
                        confidence=confidence,
                        source=f"Hop #{hop.hop_number}",
                        basis=[
                            "received_header",
                            "public_routable_ip",
                            "earliest_observed_public_relay_hop"
                        ]
                    )
                    break

        return ip_records, probable_origin

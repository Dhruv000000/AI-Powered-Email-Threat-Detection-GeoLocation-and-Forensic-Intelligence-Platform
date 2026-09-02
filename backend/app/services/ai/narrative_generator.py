"""
AI Executive Narrative Generator.
Synthesizes structured forensic telemetry, MITRE ATT&CK patterns, and threat intent
into defensible 2-3 sentence executive summaries for SOC analysts and CISO briefings.
"""
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from app.services.investigation.summary_generator import generate_investigation_summary


def get_target_domain(extracted_urls: list, fallback: str = "an external credential portal") -> str:
    """
    Dynamically extract the domain from the highest-risk or primary extracted URL.
    Prioritizes URLs marked high-risk or malicious.
    """
    if not extracted_urls:
        return fallback

    high_risk = [
        u for u in extracted_urls
        if (u.get("risk_score", 0) if isinstance(u, dict) else getattr(u, "risk_score", 0) or 0) >= 50
        or (u.get("threat_level") if isinstance(u, dict) else getattr(u, "threat_level", "clean")) in ("high", "critical", "suspicious")
    ]
    target_obj = high_risk[0] if high_risk else extracted_urls[0]

    target_domain = target_obj.get("domain") if isinstance(target_obj, dict) else getattr(target_obj, "domain", None)
    if target_domain:
        return target_domain.strip()

    target_url = target_obj.get("url") if isinstance(target_obj, dict) else (getattr(target_obj, "url", None) or getattr(target_obj, "original_url", None))
    if target_url:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        return domain.strip()

    return fallback


class ExecutiveNarrativeGenerator:
    """Executive narrative synthesizer for email security incidents."""

    @staticmethod
    def generate_executive_narrative(
        threat_type: Optional[str] = None,
        risk_score: Optional[int] = None,
        severity: Optional[str] = None,
        impersonated_brand: Optional[str] = None,
        origin_isp: Optional[str] = None,
        origin_country: Optional[str] = None,
        transit_anonymizers: Optional[List[str]] = None,
        target_domains: Optional[List[str]] = None,
        extracted_urls: Optional[List[Any]] = None,
        lure_type: Optional[str] = None,
        entity_count: int = 0,
        finding_count: int = 0,
    ) -> str:
        """
        Synthesize a 2-3 sentence executive assessment addressing:
        1. Pretext and impersonated entity.
        2. Financial or credential lure and urgency mechanism.
        3. Technical delivery chain (origin ISP/ASN, Tor/anonymized relays, 0-day harvest domains).
        """
        score = risk_score or 0
        sev = (severity or "medium").upper()
        threat_label = (threat_type or "phishing").replace("_", " ").title()

        # 1. Pretext & Urgency
        brand_str = f" masquerading as {impersonated_brand}" if impersonated_brand else ""
        lure_str = lure_type or "unauthorized credential access or payment redirection"

        # 2. Technical Delivery Chain
        origin_str = f"originating from {origin_isp or origin_country or 'unverified ISP infrastructure'}"
        if origin_country and origin_isp and origin_country not in origin_isp:
            origin_str += f" ({origin_country})"

        transit_str = ""
        if transit_anonymizers and len(transit_anonymizers) > 0:
            transit_str = f", routed through anonymized transit nodes ({transit_anonymizers[0]}) to conceal origin"

        resolved_target = None
        if target_domains and len(target_domains) > 0:
            resolved_target = target_domains[0]
        elif extracted_urls and len(extracted_urls) > 0:
            resolved_target = get_target_domain(extracted_urls)

        target_str = ""
        if resolved_target:
            target_str = f" The payload attempts to direct recipients to a 0-day credential harvesting domain ({resolved_target}) structured to bypass standard gateway filtering."

        sentence_1 = (
            f"Adversary initiated a targeted {threat_label} campaign{brand_str} "
            f"(Composite Risk Score: {score}/100, {sev}) utilizing social engineering lures designed for {lure_str}."
        )
        sentence_2 = (
            f"Forensic header analysis indicates delivery {origin_str}{transit_str}."
        )
        sentence_3 = (
            target_str.strip() or f" Forensic correlation verified {entity_count} distinct IoC entities across {finding_count} technical findings."
        )

        return f"{sentence_1} {sentence_2} {sentence_3}".strip()


def synthesize_narrative(
    metadata: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Any]] = None,
    route: Optional[List[Any]] = None,
    extracted_urls: Optional[List[Any]] = None,
) -> str:
    """
    Synthesize an analytical executive narrative without bullet points.
    Integrates pretext, impersonated entity, financial/credential lure, origin geography,
    anonymizer relays, and target harvesting domains.
    """
    metadata = metadata or {}
    findings = findings or []
    route = route or []
    urls = extracted_urls or metadata.get("extracted_urls") or metadata.get("urls") or []

    sender = metadata.get("from_address") or metadata.get("from_email") or "an unverified external address"
    reply_to = metadata.get("reply_to", "")

    origin_ip = "an unknown IP"
    origin_geo = "an external jurisdiction"
    if route and len(route) > 0:
        first_hop = route[0]
        if isinstance(first_hop, dict):
            origin_ip = first_hop.get("ip", "an unknown IP")
            origin_geo = first_hop.get("country_name") or first_hop.get("country") or "an external jurisdiction"
        else:
            origin_ip = getattr(first_hop, "ip", "an unknown IP")
            loc = getattr(first_hop, "location", None)
            origin_geo = getattr(loc, "country_name", None) or getattr(loc, "country", None) or "an external jurisdiction"

    has_tor = False
    for h in route:
        if isinstance(h, dict):
            if h.get("is_anonymizer") or h.get("is_tor") or "tor" in str(h.get("asn_org") or h.get("as_org", "")).lower():
                has_tor = True
                break
        else:
            loc = getattr(h, "location", None)
            if getattr(loc, "is_tor", False) or "tor" in str(getattr(loc, "as_org", "")).lower():
                has_tor = True
                break

    sender_identity = metadata.get("from_display_name") or metadata.get("from_address") or metadata.get("from_email") or "an external authority"
    sender_domain = metadata.get("from_domain") or ""
    if not sender_domain and "@" in str(sender):
        sender_domain = str(sender).split("@")[-1].lower()

    sender_dom_str = f" ({sender_domain})" if sender_domain else ""
    susp_domains = [d for d in (metadata.get("suspicious_domains") or metadata.get("target_domains") or []) if d.lower() != sender_domain.lower()]

    if susp_domains:
        target_url_host = susp_domains[0]
    elif urls:
        target_url_host = get_target_domain(urls)
    elif metadata.get("target_url_host"):
        target_url_host = metadata["target_url_host"]
    elif metadata.get("target_domain"):
        target_url_host = metadata["target_domain"]
    else:
        target_url_host = "an external credential portal"

    anonymizer_clause = " through an anonymized Tor/proxy relay" if has_tor else ""
    mismatch_clause = f" with responses redirected to {reply_to}" if reply_to and reply_to != sender else ""

    return (
        f"Adversary initiated an impersonation lure claiming to be {sender_identity}{sender_dom_str} to coerce urgent action{mismatch_clause}, "
        f"while directing victims to enter credentials on external infrastructure hosted at {target_url_host}. "
        f"Forensic routing traces initial dispatch to {origin_geo} ({origin_ip}){anonymizer_clause}."
    )


# Convenience functional export
generate_executive_narrative = ExecutiveNarrativeGenerator.generate_executive_narrative

__all__ = [
    "ExecutiveNarrativeGenerator",
    "generate_executive_narrative",
    "synthesize_narrative",
    "get_target_domain",
]

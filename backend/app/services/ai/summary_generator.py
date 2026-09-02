"""
Unified AI Canonical SOC Narrative Summary Service.
Provides a single, shared generator for both the Email Analysis endpoint and DFIR Investigation Reports.
Guarantees consistent dynamic variable interpolation across sender envelopes, threat verbs,
delivery relay routing, Tor/proxy transit, and primary target infrastructure domains.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def extract_primary_target_domain(extracted_urls: list) -> str:
    """
    Extract the primary or highest-risk target infrastructure domain from extracted URLs.
    Prioritizes high-risk, suspicious, or lookalike URLs before standard links.
    """
    if not extracted_urls:
        return "external infrastructure"

    def get_field(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    high_risk = [
        u for u in extracted_urls
        if (get_field(u, "risk_score", 0) or 0) >= 50
        or get_field(u, "threat_level", "clean") in ("high", "critical", "suspicious")
        or get_field(u, "is_lookalike", False)
    ]
    candidate = high_risk[0] if high_risk else extracted_urls[0]

    raw_url = (
        get_field(candidate, "url")
        or get_field(candidate, "domain")
        or get_field(candidate, "original_url")
        or get_field(candidate, "normalized_url")
        or ""
    )

    if raw_url:
        try:
            parsed = urlparse(raw_url if "://" in str(raw_url) else f"http://{raw_url}")
            domain = parsed.netloc or parsed.path.split("/")[0]
            # Strip port if present
            domain = domain.split(":")[0].strip()
            if domain:
                return domain
        except Exception:
            pass

    return "external infrastructure"


def generate_canonical_soc_summary(analysis_data: Any) -> str:
    """
    Generate a canonical, unified SOC executive summary narrative.
    Shared across Email Analysis (Analyze View) and DFIR Investigation Report generation.
    """
    def get_attr(obj, key, default=None):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    # 1. Extract Classification & Risk
    classification = get_attr(analysis_data, "classification", {})
    risk_score = get_attr(classification, "risk_score", None)
    if risk_score is None:
        risk_score = get_attr(analysis_data, "risk_score", 0)

    severity = (get_attr(classification, "severity") or get_attr(analysis_data, "severity") or "medium").upper()
    threat_type = (get_attr(classification, "threat_type") or get_attr(analysis_data, "threat_type") or "phishing").replace("_", " ").title()

    # 2. Extract Sender Metadata
    meta = (
        get_attr(analysis_data, "email", None)
        or get_attr(analysis_data, "metadata_record", None)
        or get_attr(analysis_data, "metadata", None)
        or {}
    )
    sender_email = get_attr(meta, "from_email") or get_attr(meta, "from_address") or ""
    sender_name = get_attr(meta, "from_display_name") or get_attr(meta, "from_name") or ""
    reply_to = get_attr(meta, "reply_to") or ""

    sender_display = sender_name or sender_email or "an external authority"
    sender_domain = get_attr(meta, "from_domain") or ""
    if not sender_domain and "@" in str(sender_email):
        sender_domain = str(sender_email).split("@")[-1].lower()

    sender_dom_str = f" ({sender_domain})" if sender_domain else ""

    # 3. Extract Relay Hops & Origin
    hops = get_attr(analysis_data, "relay_path", None) or get_attr(analysis_data, "relay_hops", None) or []
    origin_ip = "an unknown IP"
    origin_geo = "an external jurisdiction"
    has_tor = False

    if hops and len(hops) > 0:
        first_hop = hops[0]
        origin_ip = get_attr(first_hop, "ip") or "an unknown IP"
        loc = get_attr(first_hop, "location", {})
        origin_geo = (
            get_attr(loc, "country_name")
            or get_attr(loc, "country")
            or get_attr(first_hop, "country_name")
            or get_attr(first_hop, "country")
            or "an external jurisdiction"
        )

        for h in hops:
            h_loc = get_attr(h, "location", {})
            if (
                get_attr(h, "is_anonymizer")
                or get_attr(h, "is_tor")
                or get_attr(h_loc, "is_tor")
                or "tor" in str(get_attr(h_loc, "as_org", "")).lower()
                or "proxy" in str(get_attr(h_loc, "as_org", "")).lower()
            ):
                has_tor = True
                break
    else:
        prob_origin = get_attr(analysis_data, "probable_origin", {})
        if prob_origin:
            origin_ip = get_attr(prob_origin, "ip") or origin_ip
            loc = get_attr(prob_origin, "location", {})
            origin_geo = get_attr(loc, "country_name") or get_attr(loc, "country") or origin_geo

    # 4. Extract URLs & Dynamic Target Domain
    indicators = get_attr(analysis_data, "indicators", {})
    extracted_urls = (
        get_attr(indicators, "urls", None)
        or get_attr(analysis_data, "extracted_urls", None)
        or get_attr(analysis_data, "urls", None)
        or []
    )

    target_domain = extract_primary_target_domain(extracted_urls)
    # If target domain happens to match the sender's own domain, look for external candidate URLs
    if target_domain and sender_domain and target_domain.lower() == sender_domain.lower():
        other_urls = [
            u for u in extracted_urls
            if (get_attr(u, "domain") or "").lower() != sender_domain.lower()
        ]
        if other_urls:
            target_domain = extract_primary_target_domain(other_urls)

    # 5. Clean Evaluation Baseline (only if no external destination URLs or indicators exist)
    if (risk_score or 0) < 25 and threat_type.lower() in ("benign", "clean") and target_domain == "external infrastructure":
        return "Forensic evaluation concluded with no deceptive signals, authentication anomalies, or malicious artifacts detected."

    # 6. Synthesize Canonical SOC Narrative
    anonymizer_clause = " through an anonymized Tor/proxy relay" if has_tor else ""
    mismatch_clause = f" with responses redirected to {reply_to}" if reply_to and reply_to != sender_email else ""

    narrative = (
        f"Adversary initiated a targeted {threat_type} impersonation lure claiming to be {sender_display}{sender_dom_str} "
        f"(Composite Risk Score: {risk_score}/100, {severity}) to coerce urgent action{mismatch_clause}, "
        f"while directing victims to enter credentials on external infrastructure hosted at {target_domain}. "
        f"Forensic routing traces initial dispatch to {origin_geo} ({origin_ip}){anonymizer_clause}."
    )
    return narrative


__all__ = [
    "extract_primary_target_domain",
    "generate_canonical_soc_summary",
]

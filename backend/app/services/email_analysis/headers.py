import re
import ipaddress
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Tuple, Optional
from app.schemas.email_analysis import RelayHopSchema, AuthenticationResultsSchema, AuthStatusItem

class HeaderAnalyzer:
    """Forensic analyzer for Received SMTP relay chains and Authentication-Results headers."""

    # Regex patterns for Received header token extraction
    _FROM_PATTERN = re.compile(r"from\s+([^\s\(\)]+)(?:\s+\((?:[^\)]*?\[(?P<ip>[0-9a-fA-F\.:]+)\]|[^\)]*?)\))?", re.IGNORECASE)
    _BY_PATTERN = re.compile(r"by\s+([^\s\(\)]+)", re.IGNORECASE)
    _IP_PATTERN = re.compile(r"\[([0-9a-fA-F\.:]+)\]")
    _WITH_PATTERN = re.compile(r"with\s+([^\s;]+)", re.IGNORECASE)

    @classmethod
    def analyze_relay_hops(cls, raw_headers: List[Tuple[str, str]]) -> List[RelayHopSchema]:
        """Extract and sequence Received headers (Hop 1 = earliest origin hop)."""
        received_headers = [val for name, val in raw_headers if name.lower() == "received"]
        
        # In SMTP, Received headers are prepended by each relay.
        # Thus, reversing them gives chronological order: hop 1 = sender's original submission server.
        chronological = list(reversed(received_headers))
        hops: List[RelayHopSchema] = []

        prev_datetime = None

        for idx, raw_val in enumerate(chronological, start=1):
            cleaned = " ".join(raw_val.split())
            
            # Extract From / By / IP / Protocol / Date
            from_server = None
            by_server = None
            ip_str = None
            protocol = None
            date_str = None
            hop_dt = None
            delay_sec = 0

            # Split timestamp after semicolon
            if ";" in cleaned:
                parts = cleaned.rsplit(";", 1)
                routing_part = parts[0].strip()
                date_str = parts[1].strip()
                try:
                    hop_dt = parsedate_to_datetime(date_str)
                    if prev_datetime and hop_dt:
                        diff = (hop_dt - prev_datetime).total_seconds()
                        delay_sec = max(0, int(diff))
                    prev_datetime = hop_dt
                except Exception:
                    pass
            else:
                routing_part = cleaned

            # Extract From Server
            from_match = re.search(r"from\s+([^\s;]+)", routing_part, re.IGNORECASE)
            if from_match:
                from_server = from_match.group(1).rstrip(";()")

            # Extract By Server
            by_match = re.search(r"by\s+([^\s;]+)", routing_part, re.IGNORECASE)
            if by_match:
                by_server = by_match.group(1).rstrip(";()")

            # Extract Protocol (e.g. ESMTP, ESMTPS, HTTP, UTF8SMTPA)
            proto_match = cls._WITH_PATTERN.search(routing_part)
            if proto_match:
                protocol = proto_match.group(1)

            # Extract IP from brackets [x.x.x.x], parentheses (x.x.x.x), or standalone tokens
            candidate_ips = re.findall(r"\[([0-9a-fA-F\.:]+)\]|\(([0-9a-fA-F\.:]+)\)|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", routing_part)
            for cand_tuple in candidate_ips:
                cand = cand_tuple if isinstance(cand_tuple, str) else next((c for c in cand_tuple if c), "")
                cand = cand.strip().strip("[]()")
                if not cand:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(cand)
                    ip_str = str(ip_obj)
                    break
                except ValueError:
                    continue

            is_private = False
            if ip_str:
                try:
                    is_private = ipaddress.ip_address(ip_str).is_private
                except ValueError:
                    pass

            is_origin = (idx == 1)
            is_anomaly = False
            anomaly_reason = None

            # Anomaly check: unreasonable transit delay > 1 hour
            if delay_sec > 3600:
                is_anomaly = True
                anomaly_reason = f"Unusual transit delay ({delay_sec // 60} minutes) before delivery."

            hops.append(
                RelayHopSchema(
                    hop_number=idx,
                    from_server=from_server,
                    by_server=by_server,
                    ip=ip_str,
                    is_private_ip=is_private,
                    timestamp=date_str,
                    protocol=protocol,
                    delay_seconds=delay_sec,
                    is_origin_node=is_origin,
                    is_anomaly=is_anomaly,
                    anomaly_reason=anomaly_reason,
                    raw_header=cleaned,
                )
            )

        return hops

    @classmethod
    def analyze_authentication(cls, raw_headers: List[Tuple[str, str]]) -> AuthenticationResultsSchema:
        """Parse SPF, DKIM, and DMARC verification results strictly from headers."""
        headers_dict = {name.lower(): val for name, val in raw_headers}
        
        spf_status = "unknown"
        spf_details = None
        
        dkim_status = "unknown"
        dkim_details = None
        
        dmarc_status = "unknown"
        dmarc_details = None
        dmarc_policy = None

        # 1. Inspect Authentication-Results
        auth_results = [val for name, val in raw_headers if name.lower() == "authentication-results"]
        for ar in auth_results:
            ar_lower = ar.lower()
            
            # SPF in Authentication-Results
            if "spf=" in ar_lower:
                match = re.search(r"spf=([a-zA-Z]+)", ar_lower)
                if match:
                    spf_status = match.group(1).lower()
                    spf_details = ar.strip()

            # DKIM in Authentication-Results
            if "dkim=" in ar_lower:
                match = re.search(r"dkim=([a-zA-Z]+)", ar_lower)
                if match:
                    dkim_status = match.group(1).lower()
                    dkim_details = ar.strip()

            # DMARC in Authentication-Results
            if "dmarc=" in ar_lower:
                match = re.search(r"dmarc=([a-zA-Z]+)", ar_lower)
                if match:
                    dmarc_status = match.group(1).lower()
                    dmarc_details = ar.strip()

        # 2. Inspect Received-SPF if SPF still unknown or to supplement
        if spf_status == "unknown" and "received-spf" in headers_dict:
            spf_val = headers_dict["received-spf"].lower()
            for cand in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                if cand in spf_val:
                    spf_status = cand
                    spf_details = headers_dict["received-spf"].strip()
                    break

        # 3. Inspect DKIM-Signature presence
        if dkim_status == "unknown":
            if "dkim-signature" in headers_dict:
                # If DKIM header is present but no auth result, mark neutral/unverified
                dkim_status = "neutral"
                dkim_details = "DKIM-Signature header present on message"
            else:
                dkim_status = "none"
                dkim_details = "No DKIM signature attached to message"

        return AuthenticationResultsSchema(
            spf=AuthStatusItem(status=spf_status, details=spf_details),
            dkim=AuthStatusItem(status=dkim_status, details=dkim_details),
            dmarc=AuthStatusItem(status=dmarc_status, details=dmarc_details, policy=dmarc_policy),
        )

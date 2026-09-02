from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.email_analysis import EmailAnalysisResponse
from app.services.geo.geo_resolver import geo_resolver


def generate_investigation_summary(
    threat_type: Optional[str] = None,
    risk_score: Optional[int] = None,
    severity: Optional[str] = None,
    entity_count: int = 0,
    threat_path_count: int = 0,
    finding_count: int = 0,
    origin_geo: Optional[Any] = None,
    relay_anomalies: Optional[List[str]] = None,
    target_domains: Optional[List[str]] = None,
    sender_identity: Optional[str] = None,
    sender_domain: Optional[str] = None,
    target_url_host: Optional[str] = None,
    intent: Optional[str] = None,
) -> str:
    """
    Generate a concise 2-sentence SOC executive summary narrative.
    Explicitly distinguishes the spoofed From sender identity/domain from the malicious destination target URL domain.
    """
    threat_type_label = (threat_type or "suspicious").replace("_", " ").title()
    score = risk_score or 0
    sev_label = (severity or "medium").upper()

    sender_id_str = sender_identity or "an external authority"
    sender_dom_str = f" ({sender_domain})" if sender_domain else ""
    target_host_str = target_url_host or (target_domains[0] if target_domains and len(target_domains) > 0 else "external credential infrastructure")

    origin_str = f" traces to {origin_geo.as_org or origin_geo.country_name} in {origin_geo.country_name}" if origin_geo and getattr(origin_geo, "country_name", None) else ""
    transit_str = f", routed through {relay_anomalies[0]} to mask provenance" if relay_anomalies and len(relay_anomalies) > 0 else ""

    sentence_1 = (
        f"Adversary initiated a targeted {threat_type_label} impersonation lure claiming to be {sender_id_str}{sender_dom_str} to coerce urgent action, "
        f"while directing victims to enter credentials on external infrastructure hosted at {target_host_str}."
    )
    sentence_2 = (
        f"Forensic header and route analysis{origin_str}{transit_str}, "
        f"correlating {entity_count} distinct entities across {threat_path_count} threat paths with {finding_count} evidentiary findings "
        f"(Composite Risk Score: {score}/100, {sev_label})."
    )

    return f"{sentence_1} {sentence_2}"


class SummaryEngine:
    """
    Forensic Summary Engine.
    Aggregates Task 01 authoritative threat metrics, computes evidence completeness confidence,
    summarizes entity and finding distributions, and builds an evidentiary chronological timeline.
    """

    def __init__(
        self,
        analysis: Union[EmailAnalysisModel, EmailAnalysisResponse, Dict[str, Any]],
        investigation_id: str,
        entities: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        threat_paths: List[Dict[str, Any]],
        investigation_created_at: Optional[datetime] = None,
    ):
        self.analysis = analysis
        if isinstance(analysis, dict):
            self.analysis_id = analysis.get("analysis_id", "ANL-UNKNOWN")
            self.risk_score = analysis.get("risk_score")
            self.threat_type = analysis.get("threat_type")
            self.severity = analysis.get("severity")
            self.ai_confidence = analysis.get("ai_confidence")
            self.metadata_obj = analysis.get("metadata") or analysis.get("metadata_record")
            self.relay_hops = analysis.get("relay_hops") or []
            self.authentication = analysis.get("authentication")
            self.sha256 = analysis.get("sha256")
            self.completed_at = analysis.get("completed_at")
        else:
            self.analysis_id = getattr(analysis, "analysis_id", "ANL-UNKNOWN")
            self.risk_score = getattr(analysis, "risk_score", None)
            self.threat_type = getattr(analysis, "threat_type", None)
            self.severity = getattr(analysis, "severity", None)
            self.ai_confidence = getattr(analysis, "ai_confidence", None)
            self.metadata_obj = getattr(analysis, "metadata_record", None) or getattr(analysis, "metadata", None)
            self.relay_hops = getattr(analysis, "relay_hops", []) or []
            self.authentication = getattr(analysis, "authentication", None)
            self.sha256 = getattr(analysis, "sha256", None)
            self.completed_at = getattr(analysis, "completed_at", None)

        self.investigation_id = investigation_id
        self.entities = entities
        self.findings = findings
        self.threat_paths = threat_paths
        self.investigation_created_at = investigation_created_at or datetime.now(timezone.utc)

    def compute_investigation_confidence(self) -> float:
        """
        Computes evidence completeness confidence based on presence of headers, authentication,
        relay hops, and cryptographic evidence seals.
        """
        score = 0.50  # Baseline
        if self.metadata_obj:
            score += 0.15
        
        spf_status = None
        if self.authentication:
            spf_status = getattr(self.authentication, "spf_status", None) if not isinstance(self.authentication, dict) else self.authentication.get("spf_status")
        if spf_status and spf_status != "unknown":
            score += 0.15
        
        if len(self.relay_hops) > 0:
            score += 0.10
        if self.sha256:
            score += 0.10
        return min(round(score, 2), 1.0)

    def generate_timeline(self) -> List[Dict[str, Any]]:
        """
        Builds chronological timeline derived strictly from evidence timestamps that actually exist.
        """
        timeline = []
        meta = self.metadata_obj

        date_header = None
        if meta:
            date_header = getattr(meta, "date_header", None) if not isinstance(meta, dict) else (meta.get("date_header") or meta.get("date"))

        # 1. Email Date Header
        if date_header:
            timeline.append({
                "id": "tl-evt-1",
                "timestamp": str(date_header),
                "title": "Email Message Date Header",
                "event_type": "email_received",
                "description": f"RFC 822 Date header observed in message headers: '{date_header}'.",
                "source": "email_headers:Date",
                "evidence_reference": "email_metadata:date_header",
            })

        # 2. Relay Hops Timestamps
        for hop in self.relay_hops:
            ts = getattr(hop, "timestamp", None) if not isinstance(hop, dict) else hop.get("timestamp")
            hop_num = getattr(hop, "hop_number", 1) if not isinstance(hop, dict) else hop.get("hop_number", 1)
            server = getattr(hop, "by_server", None) or getattr(hop, "from_server", "relay") if not isinstance(hop, dict) else (hop.get("by_server") or hop.get("from_server", "relay"))
            if ts:
                timeline.append({
                    "id": f"tl-evt-hop-{hop_num}",
                    "timestamp": str(ts),
                    "title": f"SMTP Relay Hop #{hop_num} Observed",
                    "event_type": "header_observed",
                    "description": f"Received header transit logged via server '{server}'.",
                    "source": f"email_relay_hops:hop_{hop_num}",
                    "evidence_reference": f"email_relay_hops:hop_{hop_num}",
                })

        # 3. Task 01 Analysis Completed
        if self.completed_at:
            ts_str = self.completed_at.isoformat().replace("T", " ")[:19] + " UTC" if hasattr(self.completed_at, "isoformat") else str(self.completed_at)
            timeline.append({
                "id": "tl-evt-analysis-completed",
                "timestamp": ts_str,
                "title": "Task 01 Forensic Analysis Completed",
                "event_type": "analysis_completed",
                "description": f"Classification determined: {self.threat_type or 'suspicious'} (Score: {self.risk_score}/100).",
                "source": "aegis-email-analysis-engine",
                "evidence_reference": f"email_analyses:{self.analysis_id}",
            })

        # 4. Investigation Created
        inv_ts_str = self.investigation_created_at.isoformat().replace("T", " ")[:19] + " UTC"
        timeline.append({
            "id": "tl-evt-investigation-started",
            "timestamp": inv_ts_str,
            "title": "Threat Investigation Engine Initialized",
            "event_type": "investigation_started",
            "description": f"Evidence correlation graph and findings generated for investigation '{self.investigation_id}'.",
            "source": "aegis-investigation-engine",
            "evidence_reference": f"investigations:{self.investigation_id}",
        })

        return timeline

    def generate_summary(self) -> Dict[str, Any]:
        # Entity counts by type (ensuring both IP and IPAddress keys are present)
        raw_counts = Counter(e.get("type", "Unknown") for e in self.entities)
        entity_counts = dict(raw_counts)
        ip_count = entity_counts.get("IP", 0) + entity_counts.get("IPAddress", 0)
        if ip_count > 0:
            entity_counts["IP"] = ip_count
            entity_counts["IPAddress"] = ip_count

        # Finding counts by severity
        finding_counts = dict(Counter(f.get("severity", "medium") for f in self.findings))

        # Top findings (sorted by severity rank)
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "moderate": 1, "low": 0}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_rank.get(f.get("severity", "medium").lower(), 1),
            reverse=True,
        )
        top_findings = sorted_findings[:5]

        # Key threat paths
        key_threat_paths = self.threat_paths[:3]

        # Telemetry Extraction for Narrative Synthesis
        origin_ip = None
        for e in self.entities:
            if e.get("type") in ("IP", "IPAddress") and e.get("is_origin"):
                origin_ip = e.get("normalized_value")
                break
        if not origin_ip and len(self.relay_hops) > 0:
            first_hop = self.relay_hops[0]
            origin_ip = getattr(first_hop, "ip", None) if not isinstance(first_hop, dict) else first_hop.get("ip")

        origin_geo = geo_resolver.resolve_ip(origin_ip) if origin_ip else None

        relay_anomalies = []
        for h in self.relay_hops:
            h_ip = getattr(h, "ip", None) if not isinstance(h, dict) else h.get("ip")
            if h_ip:
                g = geo_resolver.resolve_ip(h_ip)
                if g.is_tor or g.asn in (60729, 208323):
                    asn_label = f"AS{g.asn}" if g.asn else "Tor/Proxy"
                    relay_anomalies.append(f"{asn_label} ({g.as_org or 'Anonymizer'})")

        # Resolve Sender Identity & Domain
        sender_identity = None
        sender_domain = None
        if self.metadata_obj:
            sender_identity = (
                getattr(self.metadata_obj, "from_display_name", None)
                or (self.metadata_obj.get("from_display_name") if isinstance(self.metadata_obj, dict) else None)
                or getattr(self.metadata_obj, "from_email", None)
                or (self.metadata_obj.get("from_email") if isinstance(self.metadata_obj, dict) else None)
            )
            sender_domain = (
                getattr(self.metadata_obj, "from_domain", None)
                or (self.metadata_obj.get("from_domain") if isinstance(self.metadata_obj, dict) else None)
            )
            if not sender_domain:
                from_em = getattr(self.metadata_obj, "from_email", "") or (self.metadata_obj.get("from_email", "") if isinstance(self.metadata_obj, dict) else "")
                if "@" in str(from_em):
                    sender_domain = str(from_em).split("@")[-1].lower()

        # Resolve Malicious Destination Target URL Domain (explicitly distinct from sender domain)
        from app.services.ai.narrative_generator import get_target_domain

        target_url_host = None
        # Check URLs from analysis model or entities
        analysis_urls = (
            getattr(self.analysis, "extracted_urls", None)
            or getattr(self.analysis, "urls", None)
            or (self.analysis.get("extracted_urls") if isinstance(self.analysis, dict) else None)
        )
        if analysis_urls:
            candidate = get_target_domain(analysis_urls)
            if candidate and candidate != "an external credential portal":
                target_url_host = candidate

        if not target_url_host:
            for e in self.entities:
                if e.get("type") in ("URL", "Domain"):
                    val = str(e.get("normalized_value", "")).lower()
                    dom = val.split("://")[-1].split("/")[0].split(":")[0]
                    if sender_domain and dom == sender_domain.lower():
                        continue
                    if e.get("is_suspicious") or (e.get("risk_score") or 0) >= 40:
                        target_url_host = dom
                        break
                    if not target_url_host and dom:
                        target_url_host = dom

        target_domains = []
        if target_url_host:
            target_domains.append(target_url_host)
        for e in self.entities:
            if e.get("type") == "Domain" and e.get("is_suspicious"):
                if e.get("normalized_value") not in target_domains:
                    target_domains.append(e.get("normalized_value"))

        # Synchronize Attachment and IOC metrics strictly with heuristic findings
        attachments_count = sum(1 for e in self.entities if e.get("type") in ("File", "Attachment"))
        malicious_attachments_count = 0
        for e in self.entities:
            if e.get("type") in ("File", "Attachment"):
                fname = e.get("name") or e.get("normalized_value") or e.get("display_label") or ""
                if e.get("is_malicious") or e.get("is_suspicious") or any(f.get("finding_code") in ("DOUBLE_EXTENSION", "SUSPICIOUS_DOUBLE_EXTENSION", "EXECUTABLE_ATTACHMENT", "MALICIOUS_ATTACHMENT", "SUSPICIOUS_ATTACHMENT") for f in self.findings):
                    malicious_attachments_count += 1
                elif any(ext in fname.lower() for ext in (".pdf.vbs", ".pdf.exe", ".doc.exe", ".zip", ".iso")):
                    malicious_attachments_count += 1

        if attachments_count == 0 and getattr(self.analysis, "attachments", None):
            attachments_count = len(self.analysis.attachments)
            malicious_attachments_count = sum(
                1 for a in self.analysis.attachments
                if getattr(a, "is_suspicious", False) or getattr(a, "is_executable", False) or getattr(a, "is_double_extension", False)
            )

        if malicious_attachments_count == 0 and any(f.get("finding_code") in ("DOUBLE_EXTENSION", "SUSPICIOUS_DOUBLE_EXTENSION", "EXECUTABLE_ATTACHMENT", "MALICIOUS_ATTACHMENT", "SUSPICIOUS_ATTACHMENT") for f in self.findings):
            malicious_attachments_count = max(1, attachments_count)
            if attachments_count == 0:
                attachments_count = 1

        high_risk_links = 0
        for e in self.entities:
            if e.get("type") in ("URL", "Domain") and (e.get("is_suspicious") or (e.get("risk_score") or 0) >= 50):
                high_risk_links += 1
        if high_risk_links == 0 and any(f.get("finding_code") in ("SUSPICIOUS_URL", "PHISHING_LINK", "MALICIOUS_DOMAIN", "CREDENTIAL_HARVESTING_URL", "ZERO_DAY_DOMAIN") for f in self.findings):
            high_risk_links = sum(1 for f in self.findings if f.get("finding_code") in ("SUSPICIOUS_URL", "PHISHING_LINK", "MALICIOUS_DOMAIN", "CREDENTIAL_HARVESTING_URL", "ZERO_DAY_DOMAIN")) or 1

        # Executive summary narrative synthesized from evidence and telemetry
        executive_summary = generate_investigation_summary(
            threat_type=self.threat_type,
            risk_score=self.risk_score,
            severity=self.severity,
            entity_count=len(self.entities),
            threat_path_count=len(self.threat_paths),
            finding_count=len(self.findings),
            origin_geo=origin_geo,
            relay_anomalies=relay_anomalies,
            target_domains=target_domains,
            sender_identity=sender_identity,
            sender_domain=sender_domain,
            target_url_host=target_url_host,
        )

        return {
            "investigation_id": self.investigation_id,
            "analysis_id": self.analysis_id,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "ai_confidence": self.ai_confidence,
            "investigation_confidence": self.compute_investigation_confidence(),
            "entity_counts": entity_counts,
            "finding_counts": finding_counts,
            "top_findings": top_findings,
            "key_threat_paths": key_threat_paths,
            "timeline": self.generate_timeline(),
            "executive_summary": executive_summary,
            "attachments_count": attachments_count,
            "malicious_attachments_count": malicious_attachments_count,
            "high_risk_links": high_risk_links,
            "urls_count": entity_counts.get("URL", 0),
        }

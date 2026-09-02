import hashlib
from typing import Dict, Any, List, Optional
from app.db.models.email_analysis import EmailAnalysisModel
from app.services.investigation.entity_builder import EntityBuilder


class FindingsEngine:
    """
    Forensic Findings Engine.
    Evaluates Task 01 structured forensic evidence to generate defensible, deterministic,
    evidence-referenced investigation findings linked to graph entity and relationship IDs.
    """

    def __init__(
        self,
        analysis: EmailAnalysisModel,
        investigation_id: str,
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ):
        self.analysis = analysis
        self.analysis_id = analysis.analysis_id
        self.investigation_id = investigation_id
        self.entities_by_id = {e["id"]: e for e in entities}
        self.relationships = relationships
        self._findings: List[Dict[str, Any]] = []

    def _make_finding_id(self, reason_code: str, suffix: str = "") -> str:
        raw = f"{self.investigation_id}:{reason_code}:{suffix}"
        hash_val = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8].upper()
        return f"FND-{reason_code}-{hash_val}"

    def _find_entity_ids_by_type(self, entity_type: str) -> List[str]:
        return [e["id"] for e in self.entities_by_id.values() if e.get("type") == entity_type]

    def _find_entity_ids_by_value(self, value_substring: str) -> List[str]:
        val_lower = value_substring.lower()
        return [
            e["id"] for e in self.entities_by_id.values()
            if val_lower in e.get("normalized_value", "").lower() or val_lower in e.get("label", "").lower()
        ]

    def _find_rel_ids(self, source_id: Optional[str] = None, target_id: Optional[str] = None, rel_type: Optional[str] = None) -> List[str]:
        matches = []
        for r in self.relationships:
            if source_id and r.get("source_id") != source_id:
                continue
            if target_id and r.get("target_id") != target_id:
                continue
            if rel_type and r.get("type") != rel_type:
                continue
            matches.append(r["id"])
        return matches

    def generate_findings(self) -> List[Dict[str, Any]]:
        self._findings.clear()
        email_id = f"email:{self.analysis_id}"
        meta = self.analysis.metadata_record
        auth = self.analysis.authentication

        # 1. Reply-To Mismatch Finding
        if meta and meta.reply_to and meta.from_email:
            norm_from, from_dom, _ = EntityBuilder.normalize_email_address(meta.from_email)
            norm_rt, rt_dom, _ = EntityBuilder.normalize_email_address(meta.reply_to)
            if norm_from and norm_rt and (from_dom != rt_dom or norm_from != norm_rt):
                rt_entity_ids = self._find_entity_ids_by_value(norm_rt) + self._find_entity_ids_by_value(norm_from)
                rt_rel_ids = self._find_rel_ids(source_id=email_id, rel_type="REPLIED_TO")
                self._findings.append({
                    "finding_id": self._make_finding_id("REPLY_TO_MISMATCH"),
                    "investigation_id": self.investigation_id,
                    "reason_code": "REPLY_TO_MISMATCH",
                    "title": "Reply-To Address Mismatch",
                    "severity": "high",
                    "description": (
                        f"Observed Reply-To header ('{norm_rt}') points to a different domain/identity than "
                        f"the envelope sender ('{norm_from}'). This is consistent with return path manipulation and BEC."
                    ),
                    "confidence": 0.95,
                    "evidence_references": ["email_metadata:reply_to", "email_metadata:from_email"],
                    "entity_ids": list(set([email_id] + rt_entity_ids)),
                    "relationship_ids": rt_rel_ids,
                })

        # 2. Authentication Failures (SPF, DKIM, DMARC)
        if auth:
            if auth.spf_status and auth.spf_status.lower() in ("fail", "softfail", "permerror"):
                spf_ent_ids = self._find_entity_ids_by_type("Domain") + [email_id]
                self._findings.append({
                    "finding_id": self._make_finding_id("SPF_FAILURE"),
                    "investigation_id": self.investigation_id,
                    "reason_code": "SPF_FAILURE",
                    "title": f"SPF Authentication Failed ({auth.spf_status.upper()})",
                    "severity": "high" if auth.spf_status.lower() == "fail" else "medium",
                    "description": (
                        f"Sender Policy Framework (SPF) validation failed ({auth.spf_status}). "
                        f"Details: {auth.spf_details or 'Originating IP is not authorized in sender domain SPF record.'}"
                    ),
                    "confidence": 0.92,
                    "evidence_references": ["email_authentication:spf_status", "email_authentication:spf_details"],
                    "entity_ids": list(set(spf_ent_ids[:3])),
                    "relationship_ids": self._find_rel_ids(rel_type="SENT"),
                })

            if auth.dkim_status and auth.dkim_status.lower() in ("fail", "permerror"):
                self._findings.append({
                    "finding_id": self._make_finding_id("DKIM_FAILURE"),
                    "investigation_id": self.investigation_id,
                    "reason_code": "DKIM_FAILURE",
                    "title": "DKIM Cryptographic Signature Failed",
                    "severity": "high",
                    "description": (
                        f"DomainKeys Identified Mail (DKIM) signature verification failed. "
                        f"Details: {auth.dkim_details or 'Cryptographic body hash or header signature mismatch detected.'}"
                    ),
                    "confidence": 0.94,
                    "evidence_references": ["email_authentication:dkim_status", "email_authentication:dkim_details"],
                    "entity_ids": [email_id],
                    "relationship_ids": self._find_rel_ids(rel_type="SENT"),
                })

            if auth.dmarc_status and auth.dmarc_status.lower() in ("fail", "quarantine", "reject"):
                self._findings.append({
                    "finding_id": self._make_finding_id("DMARC_FAILURE"),
                    "investigation_id": self.investigation_id,
                    "reason_code": "DMARC_FAILURE",
                    "title": f"DMARC Policy Alignment Failure ({auth.dmarc_status.upper()})",
                    "severity": "high",
                    "description": (
                        f"DMARC alignment failed for sender domain. Policy: '{auth.dmarc_policy or 'none'}'. "
                        f"Details: {auth.dmarc_details or 'Header From domain does not align with authenticated SPF/DKIM domains.'}"
                    ),
                    "confidence": 0.93,
                    "evidence_references": ["email_authentication:dmarc_status", "email_authentication:dmarc_policy"],
                    "entity_ids": [email_id],
                    "relationship_ids": self._find_rel_ids(rel_type="USES_DOMAIN"),
                })

        # 3. Suspicious / Lookalike Domains
        for url_rec in self.analysis.urls:
            if url_rec.is_lookalike:
                url_hash, norm_url, _, _, dom = EntityBuilder.normalize_url(url_rec.original_url or url_rec.normalized_url)
                url_id = f"url:{url_hash}"
                dom_id = f"domain:{EntityBuilder.normalize_domain(dom)}"
                rel_ids = self._find_rel_ids(source_id=url_id, target_id=dom_id) + self._find_rel_ids(source_id=email_id, target_id=url_id)
                self._findings.append({
                    "finding_id": self._make_finding_id("LOOKALIKE_DOMAIN", url_hash[:6]),
                    "investigation_id": self.investigation_id,
                    "reason_code": "LOOKALIKE_DOMAIN",
                    "title": f"Lookalike Domain Identified ({dom})",
                    "severity": "high",
                    "description": (
                        f"Extracted URL links to probable lookalike or typosquatting domain '{dom}'. "
                        f"Syntactic analysis suggests potential brand or enterprise impersonation."
                    ),
                    "confidence": 0.88,
                    "evidence_references": [f"email_urls:{url_rec.id}"],
                    "entity_ids": [email_id, url_id, dom_id],
                    "relationship_ids": rel_ids,
                })

            if url_rec.is_ip_based:
                url_hash, norm_url, _, host, _ = EntityBuilder.normalize_url(url_rec.original_url or url_rec.normalized_url)
                url_id = f"url:{url_hash}"
                ip_id = f"ip:{host}"
                self._findings.append({
                    "finding_id": self._make_finding_id("IP_BASED_URL", url_hash[:6]),
                    "investigation_id": self.investigation_id,
                    "reason_code": "IP_BASED_URL",
                    "title": "Direct IP-Based Hyperlink",
                    "severity": "medium",
                    "description": (
                        f"Observed hyperlink '{norm_url}' uses a raw IP host ('{host}') rather than a registered domain name, "
                        f"frequently used to evade DNS-level security filtering."
                    ),
                    "confidence": 0.90,
                    "evidence_references": [f"email_urls:{url_rec.id}"],
                    "entity_ids": [email_id, url_id, ip_id],
                    "relationship_ids": self._find_rel_ids(source_id=url_id, rel_type="HOSTED_ON"),
                })

        # 4. Suspicious Attachments & Executables
        for att in self.analysis.attachments:
            if att.is_suspicious or att.is_executable or att.is_double_extension:
                att_sha = EntityBuilder.normalize_hash(att.sha256)
                att_id = f"attachment:{att_sha}"
                hash_id = f"file_hash:{att_sha}"
                rel_ids = self._find_rel_ids(source_id=email_id, target_id=att_id) + self._find_rel_ids(source_id=att_id, target_id=hash_id)

                reasons = []
                if att.is_executable:
                    reasons.append("executable MIME/extension type")
                if att.is_double_extension:
                    reasons.append("masquerading double extension")
                if att.detected_signals:
                    reasons.extend(att.detected_signals)

                reason_str = ", ".join(reasons) if reasons else "suspicious payload characteristics"
                self._findings.append({
                    "finding_id": self._make_finding_id("SUSPICIOUS_ATTACHMENT", att_sha[:6]),
                    "investigation_id": self.investigation_id,
                    "finding_code": "SUSPICIOUS_ATTACHMENT",
                    "reason_code": "SUSPICIOUS_ATTACHMENT",
                    "title": f"High-Risk Attachment Detected ({att.filename})",
                    "severity": "critical" if att.is_executable or att.is_double_extension else "high",
                    "description": (
                        f"Attachment '{att.filename}' exhibits high-risk indicators: {reason_str}. "
                        f"Cryptographic SHA-256 seal: {att_sha}."
                    ),
                    "confidence": 0.95,
                    "evidence_references": [f"email_attachments:{att.id}"],
                    "entity_ids": [email_id, att_id, hash_id],
                    "relationship_ids": rel_ids,
                })

                if att.is_double_extension:
                    self._findings.append({
                        "finding_id": self._make_finding_id("SUSPICIOUS_DOUBLE_EXTENSION", att_sha[:6]),
                        "investigation_id": self.investigation_id,
                        "finding_code": "SUSPICIOUS_DOUBLE_EXTENSION",
                        "reason_code": "SUSPICIOUS_DOUBLE_EXTENSION",
                        "title": f"Deceptive Double-Extension Detected ({att.filename})",
                        "severity": "critical",
                        "description": (
                            f"Attachment '{att.filename}' employs deceptive double extension techniques to disguise executable payloads."
                        ),
                        "confidence": 0.98,
                        "evidence_references": [f"email_attachments:{att.id}"],
                        "entity_ids": [email_id, att_id, hash_id],
                        "relationship_ids": rel_ids,
                    })

        # 5. Routing Anomalies & Impossible Travel Velocity
        relay_hops = sorted(list(self.analysis.relay_hops or []), key=lambda h: h.hop_number)
        prev_geo = None
        for i, hop in enumerate(relay_hops):
            hop_ip = hop.ip
            if hop_ip:
                from app.services.geo.geo_resolver import geo_resolver, GeoResolver
                geo_dto = geo_resolver.resolve_ip(hop_ip)
                if prev_geo and prev_geo.latitude is not None and geo_dto.latitude is not None:
                    dist_km = GeoResolver.calculate_haversine_distance(
                        prev_geo.latitude, prev_geo.longitude,
                        geo_dto.latitude, geo_dto.longitude
                    )
                    delay_s = hop.delay_seconds if hop.delay_seconds is not None else 0
                    if 0 <= delay_s < 2.0 and dist_km > 4000.0:
                        self._findings.append({
                            "finding_id": self._make_finding_id("IMPOSSIBLE_TRAVEL_VELOCITY", f"hop{hop.hop_number}"),
                            "investigation_id": self.investigation_id,
                            "reason_code": "IMPOSSIBLE_TRAVEL_VELOCITY",
                            "title": "Impossible Travel Velocity Observed",
                            "severity": "high",
                            "description": (
                                f"Non-cloud network transit traversed {dist_km:.0f} km in under 2 seconds ({delay_s:.1f}s) "
                                f"between Hop #{i} ({prev_geo.country_name}) and Hop #{i+1} ({geo_dto.country_name}), "
                                f"indicating proxy bouncing, VPN switching, or Tor transit obfuscation."
                            ),
                            "confidence": 0.96,
                            "evidence_references": [f"email_relay_hops:hop_{hop.hop_number}"],
                            "entity_ids": [email_id] + self._find_entity_ids_by_value(hop_ip),
                            "relationship_ids": self._find_rel_ids(source_id=email_id, rel_type="RELAYED_THROUGH"),
                        })
                if geo_dto.latitude is not None:
                    prev_geo = geo_dto

        # 6. Task 01 ML & Forensic Reasons Integration
        for reason in self.analysis.reasons:
            code = reason.reason_code
            if code not in [f["reason_code"] for f in self._findings]:
                # Map Task 01 reason to investigation finding
                ent_ids = [email_id]
                rel_ids = []
                if "REPLY_TO" in code:
                    ent_ids.extend(self._find_entity_ids_by_type("EmailAddress"))
                    rel_ids.extend(self._find_rel_ids(rel_type="REPLIED_TO"))
                elif "URL" in code:
                    ent_ids.extend(self._find_entity_ids_by_type("URL"))
                    rel_ids.extend(self._find_rel_ids(rel_type="LINKS_TO"))
                elif "ATTACHMENT" in code:
                    ent_ids.extend(self._find_entity_ids_by_type("Attachment"))
                    rel_ids.extend(self._find_rel_ids(rel_type="HAS_ATTACHMENT"))

                self._findings.append({
                    "finding_id": self._make_finding_id(code),
                    "investigation_id": self.investigation_id,
                    "reason_code": code,
                    "title": reason.title,
                    "severity": reason.severity,
                    "description": reason.description,
                    "confidence": 0.85,
                    "evidence_references": [reason.evidence_reference or f"analysis_reasons:{code}"],
                    "entity_ids": list(set(ent_ids))[:4],
                    "relationship_ids": rel_ids[:4],
                })

        return self._findings

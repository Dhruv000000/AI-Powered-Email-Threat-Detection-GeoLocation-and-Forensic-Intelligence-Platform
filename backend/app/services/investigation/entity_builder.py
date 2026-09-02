import hashlib
import ipaddress
import re
from typing import Dict, Any, List, Tuple, Optional, Union
from urllib.parse import urlparse

from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailHeaderModel,
    EmailRelayHopModel,
    EmailAuthenticationModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
    EmailIndicatorModel,
)
from app.schemas.email_analysis import EmailAnalysisResponse


class EntityBuilder:
    """
    Forensic Entity Builder.
    Transforms Task 01 structured email analysis records (SQLAlchemy model, Pydantic response, or dict)
    into normalized, deduplicated graph entity nodes with deterministic identifiers and evidentiary provenance.
    Strictly static analysis with zero live network or DNS egress.
    """

    def __init__(self, analysis: Union[EmailAnalysisModel, EmailAnalysisResponse, Dict[str, Any]], investigation_id: str = "INV-DEFAULT"):
        self.analysis = analysis
        self.investigation_id = investigation_id
        
        # Extract core analysis attributes generically
        if isinstance(analysis, dict):
            self.analysis_id = analysis.get("analysis_id", "ANL-UNKNOWN")
            self.filename = analysis.get("filename", "")
            self.sha256 = analysis.get("sha256", "")
            
            classification = analysis.get("classification") or {}
            self.risk_score = analysis.get("risk_score", classification.get("risk_score") if isinstance(classification, dict) else getattr(classification, "risk_score", None))
            self.threat_type = analysis.get("threat_type", classification.get("threat_type") if isinstance(classification, dict) else getattr(classification, "threat_type", None))
            self.severity = analysis.get("severity", classification.get("severity") if isinstance(classification, dict) else getattr(classification, "severity", None))
            self.ai_confidence = analysis.get("ai_confidence", classification.get("ai_confidence") if isinstance(classification, dict) else getattr(classification, "ai_confidence", None))
            
            prob_orig = analysis.get("probable_origin")
            self.probable_origin_ip = analysis.get("probable_origin_ip") or (prob_orig.get("ip") if isinstance(prob_orig, dict) else getattr(prob_orig, "ip", None))
            self.probable_origin_confidence = analysis.get("probable_origin_confidence") or (prob_orig.get("confidence") if isinstance(prob_orig, dict) else getattr(prob_orig, "confidence", None))
            self.probable_origin_source = analysis.get("probable_origin_source") or (prob_orig.get("source") if isinstance(prob_orig, dict) else getattr(prob_orig, "source", None))
            
            self.metadata_obj = analysis.get("email") or analysis.get("metadata") or analysis.get("metadata_record")
            self.relay_hops = analysis.get("relay_hops") or analysis.get("relay_path") or []
            
            indicators = analysis.get("indicators") or {}
            self.urls = analysis.get("extracted_urls") or analysis.get("urls") or (indicators.get("urls") if isinstance(indicators, dict) else []) or []
            self.ips = analysis.get("extracted_ips") or analysis.get("ips") or (indicators.get("ips") if isinstance(indicators, dict) else []) or []
            self.attachments = analysis.get("attachments") or (indicators.get("attachments") if isinstance(indicators, dict) else []) or []
        else:
            self.analysis_id = getattr(analysis, "analysis_id", "ANL-UNKNOWN")
            self.filename = getattr(analysis, "filename", "")
            self.sha256 = getattr(analysis, "sha256", "")
            
            classification = getattr(analysis, "classification", None)
            self.risk_score = getattr(analysis, "risk_score", None) or (getattr(classification, "risk_score", None) if classification else None)
            self.threat_type = getattr(analysis, "threat_type", None) or (getattr(classification, "threat_type", None) if classification else None)
            self.severity = getattr(analysis, "severity", None) or (getattr(classification, "severity", None) if classification else None)
            self.ai_confidence = getattr(analysis, "ai_confidence", None) or (getattr(classification, "ai_confidence", None) if classification else None)
            
            prob_orig = getattr(analysis, "probable_origin", None)
            self.probable_origin_ip = getattr(analysis, "probable_origin_ip", None) or (getattr(prob_orig, "ip", None) if prob_orig else None)
            self.probable_origin_confidence = getattr(analysis, "probable_origin_confidence", None) or (getattr(prob_orig, "confidence", None) if prob_orig else None)
            self.probable_origin_source = getattr(analysis, "probable_origin_source", None) or (getattr(prob_orig, "source", None) if prob_orig else None)
            
            self.metadata_obj = getattr(analysis, "email", None) or getattr(analysis, "metadata_record", None) or getattr(analysis, "metadata", None)
            self.relay_hops = getattr(analysis, "relay_hops", None) or getattr(analysis, "relay_path", []) or []
            
            indicators = getattr(analysis, "indicators", None)
            ind_urls = indicators.get("urls", []) if isinstance(indicators, dict) else []
            ind_ips = indicators.get("ips", []) if isinstance(indicators, dict) else []
            ind_atts = indicators.get("attachments", []) if isinstance(indicators, dict) else []
            
            self.urls = getattr(analysis, "urls", None) or getattr(analysis, "extracted_urls", None) or ind_urls or []
            self.ips = getattr(analysis, "ips", None) or getattr(analysis, "extracted_ips", None) or ind_ips or []
            self.attachments = getattr(analysis, "attachments", None) or ind_atts or []

        self._entities: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def normalize_email_address(raw_email: str) -> Tuple[str, str, Optional[str]]:
        """
        Normalizes raw email / display name string.
        Returns (normalized_email, normalized_domain, display_name).
        Example: '"John Doe" <JDOE@Example.COM>' -> ('jdoe@example.com', 'example.com', 'John Doe')
        """
        if not raw_email:
            return "", "", None

        raw = raw_email.strip()
        display_name = None

        # Extract <email@domain.com>
        angle_match = re.search(r'<([^>]+)>', raw)
        if angle_match:
            email_part = angle_match.group(1).strip()
            name_part = raw[:angle_match.start()].strip(' "\'').strip()
            if name_part and name_part.lower() != email_part.lower():
                display_name = name_part
        else:
            email_part = raw.strip(' "\'')

        normalized_email = email_part.lower()
        domain = ""
        if "@" in normalized_email:
            parts = normalized_email.split("@", 1)
            normalized_email = f"{parts[0]}@{parts[1].rstrip('.')}"
            domain = parts[1].rstrip('.')

        return normalized_email, domain, display_name

    @staticmethod
    def normalize_domain(raw_domain: str) -> str:
        """
        Normalizes domain string.
        Strips port, leading/trailing whitespace, dots, and handles IDN punycode.
        """
        if not raw_domain:
            return ""
        domain = raw_domain.strip().lower()
        if ":" in domain:
            domain = domain.split(":", 1)[0]
        domain = domain.strip(".")
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except Exception:
            pass
        return domain

    @staticmethod
    def normalize_url(raw_url: str) -> Tuple[str, str, str, str, str]:
        """
        Strictly static URL parsing and normalization (zero network calls).
        Returns (url_hash, normalized_url, scheme, hostname, domain).
        """
        if not raw_url:
            return "", "", "", "", ""

        raw_url = raw_url.strip()
        parsed = urlparse(raw_url)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()

        # Handle hostname without port
        hostname = netloc.split(":")[0] if ":" in netloc else netloc
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""

        normalized_url = f"{scheme}://{hostname}{path}{query}"
        url_hash = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()[:16]

        # Extract base domain
        domain = hostname
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])

        return url_hash, normalized_url, scheme, hostname, domain

    @staticmethod
    def normalize_ip(raw_ip: str) -> Tuple[str, int, bool]:
        """
        Normalizes IPv4 or IPv6 address.
        Returns (normalized_ip, version, is_private).
        """
        if not raw_ip:
            return "", 4, False
        cleaned = raw_ip.strip().strip("[]")
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return str(ip_obj), ip_obj.version, ip_obj.is_private
        except ValueError:
            return cleaned, 4, False

    @staticmethod
    def normalize_hash(raw_hash: str) -> str:
        if not raw_hash:
            return ""
        return raw_hash.strip().lower()

    def _add_entity(
        self,
        entity_id: str,
        entity_type: str,
        display_label: str,
        normalized_value: str,
        risk_score: Optional[int] = None,
        severity: Optional[str] = None,
        evidence_reference: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        is_origin: bool = False,
        is_suspicious: bool = False,
    ) -> Dict[str, Any]:
        """Add or merge entity node with deterministic deduplication."""
        props = dict(properties or {})
        props["investigation_id"] = self.investigation_id
        props["analysis_id"] = self.analysis_id

        if entity_id in self._entities:
            existing = self._entities[entity_id]
            existing["investigation_id"] = self.investigation_id
            existing["analysis_id"] = self.analysis_id
            existing.setdefault("properties", {}).update(props)
            if risk_score is not None:
                if existing.get("risk_score") is None or risk_score > existing.get("risk_score", 0):
                    existing["risk_score"] = risk_score
                    existing["severity"] = severity
            if is_origin:
                existing["is_origin"] = True
            if is_suspicious:
                existing["is_suspicious"] = True
            return existing

        entity = {
            "id": entity_id,
            "investigation_id": self.investigation_id,
            "analysis_id": self.analysis_id,
            "type": entity_type,
            "label": display_label,
            "name": display_label,
            "display_label": display_label,
            "normalized_value": normalized_value,
            "risk_score": risk_score,
            "severity": severity or ("high" if (risk_score or 0) >= 70 else "medium" if (risk_score or 0) >= 40 else "low"),
            "evidence_reference": evidence_reference,
            "is_origin": is_origin,
            "is_suspicious": is_suspicious,
            "properties": props,
        }
        self._entities[entity_id] = entity
        return entity

    def build_all_entities(self) -> List[Dict[str, Any]]:
        """
        Extracts, normalizes, and deduplicates all entities from Task 01 structured record.
        """
        self._entities.clear()

        # 1. Primary Email Entity
        email_id = f"email:{self.analysis_id}"
        meta = self.metadata_obj
        
        subject = ""
        message_id = None
        date_header = None
        from_header = None
        from_email = None
        reply_to = None
        to_recipients = []

        if meta:
            if isinstance(meta, dict):
                subject = meta.get("subject") or ""
                message_id = meta.get("message_id")
                date_header = meta.get("date_header") or meta.get("date")
                from_header = meta.get("from_header")
                from_email = meta.get("from_email") or meta.get("sender")
                reply_to = meta.get("reply_to")
                to_recipients = meta.get("to_recipients") or meta.get("recipients") or []
            else:
                subject = getattr(meta, "subject", "") or ""
                message_id = getattr(meta, "message_id", None)
                date_header = getattr(meta, "date_header", None)
                from_header = getattr(meta, "from_header", None)
                from_email = getattr(meta, "from_email", None)
                reply_to = getattr(meta, "reply_to", None)
                to_recipients = getattr(meta, "to_recipients", []) or []

        subject_preview = (subject if subject else "No Subject")[:60]
        self._add_entity(
            entity_id=email_id,
            entity_type="Email",
            display_label=f"Email: {subject_preview}",
            normalized_value=self.analysis_id,
            risk_score=self.risk_score,
            severity=self.severity,
            evidence_reference=f"email_analyses:{self.analysis_id}",
            properties={
                "analysis_id": self.analysis_id,
                "subject": subject,
                "sha256": self.sha256,
                "risk_score": self.risk_score,
                "threat_type": self.threat_type,
                "received_date": date_header,
                "message_id": message_id,
                "severity": self.severity,
                "ai_confidence": self.ai_confidence,
                "filename": self.filename,
            },
            is_suspicious=(self.risk_score or 0) >= 60,
        )

        # 2. Sender, Recipients & Domains
        if meta:
            # From Address
            raw_from = from_header or from_email or ""
            if raw_from:
                norm_email, norm_domain, display_name = self.normalize_email_address(raw_from)
                if norm_email:
                    addr_hash = hashlib.sha256(norm_email.encode("utf-8")).hexdigest()[:16]
                    addr_id = f"email_address:{addr_hash}"
                    self._add_entity(
                        entity_id=addr_id,
                        entity_type="EmailAddress",
                        display_label=norm_email,
                        normalized_value=norm_email,
                        evidence_reference="email_metadata:from_header",
                        properties={
                            "address": norm_email,
                            "display_name": display_name,
                            "domain": norm_domain,
                            "role": "sender",
                        },
                    )

                    # Sender Domain
                    if norm_domain:
                        dom_id = f"domain:{norm_domain}"
                        tld = norm_domain.split(".")[-1] if "." in norm_domain else ""
                        self._add_entity(
                            entity_id=dom_id,
                            entity_type="Domain",
                            display_label=norm_domain,
                            normalized_value=norm_domain,
                            evidence_reference="email_metadata:from_domain",
                            properties={
                                "domain_name": norm_domain,
                                "is_lookalike": False,
                                "tld": tld,
                                "role": "sender_domain",
                            },
                        )

                    # Sender Person (if display name is present)
                    if display_name:
                        person_hash = hashlib.sha256(display_name.lower().encode("utf-8")).hexdigest()[:16]
                        person_id = f"person:{person_hash}"
                        self._add_entity(
                            entity_id=person_id,
                            entity_type="Person",
                            display_label=display_name,
                            normalized_value=display_name.lower(),
                            evidence_reference="email_metadata:from_display_name",
                            properties={"display_name": display_name},
                        )

            # Reply-To Address & Domain (if distinct)
            if reply_to:
                rt_norm, rt_domain, rt_disp = self.normalize_email_address(reply_to)
                if rt_norm:
                    rt_hash = hashlib.sha256(rt_norm.encode("utf-8")).hexdigest()[:16]
                    rt_id = f"email_address:{rt_hash}"
                    self._add_entity(
                        entity_id=rt_id,
                        entity_type="EmailAddress",
                        display_label=rt_norm,
                        normalized_value=rt_norm,
                        evidence_reference="email_metadata:reply_to",
                        properties={
                            "address": rt_norm,
                            "display_name": rt_disp,
                            "domain": rt_domain,
                            "role": "reply_to",
                        },
                        is_suspicious=True,
                    )
                    if rt_domain:
                        rt_dom_id = f"domain:{rt_domain}"
                        tld = rt_domain.split(".")[-1] if "." in rt_domain else ""
                        self._add_entity(
                            entity_id=rt_dom_id,
                            entity_type="Domain",
                            display_label=rt_domain,
                            normalized_value=rt_domain,
                            evidence_reference="email_metadata:reply_to",
                            properties={
                                "domain_name": rt_domain,
                                "is_lookalike": False,
                                "tld": tld,
                                "role": "reply_to_domain",
                            },
                        )

            # To Recipients
            if to_recipients and isinstance(to_recipients, list):
                for raw_to in to_recipients:
                    t_norm, t_domain, t_disp = self.normalize_email_address(str(raw_to))
                    if t_norm:
                        t_hash = hashlib.sha256(t_norm.encode("utf-8")).hexdigest()[:16]
                        t_id = f"email_address:{t_hash}"
                        self._add_entity(
                            entity_id=t_id,
                            entity_type="EmailAddress",
                            display_label=t_norm,
                            normalized_value=t_norm,
                            evidence_reference="email_metadata:to_recipients",
                            properties={
                                "address": t_norm,
                                "display_name": t_disp,
                                "domain": t_domain,
                                "role": "recipient",
                            },
                        )
                        if t_domain:
                            t_dom_id = f"domain:{t_domain}"
                            tld = t_domain.split(".")[-1] if "." in t_domain else ""
                            self._add_entity(
                                entity_id=t_dom_id,
                                entity_type="Domain",
                                display_label=t_domain,
                                normalized_value=t_domain,
                                evidence_reference="email_metadata:to_recipients",
                                properties={
                                    "domain_name": t_domain,
                                    "is_lookalike": False,
                                    "tld": tld,
                                    "role": "recipient_domain",
                                },
                            )

        # 3. Relay Hops & Mail Servers
        for hop in self.relay_hops:
            by_server = getattr(hop, "by_server", None) if not isinstance(hop, dict) else hop.get("by_server")
            from_server = getattr(hop, "from_server", None) if not isinstance(hop, dict) else hop.get("from_server")
            hop_ip = getattr(hop, "ip", None) if not isinstance(hop, dict) else hop.get("ip")
            hop_num = getattr(hop, "hop_number", 1) if not isinstance(hop, dict) else hop.get("hop_number", 1)
            is_origin = getattr(hop, "is_origin_node", False) if not isinstance(hop, dict) else hop.get("is_origin_node", False)
            is_anomaly = getattr(hop, "is_anomaly", False) if not isinstance(hop, dict) else hop.get("is_anomaly", False)
            protocol = getattr(hop, "protocol", "ESMTP") if not isinstance(hop, dict) else hop.get("protocol", "ESMTP")
            delay = getattr(hop, "delay_seconds", 0.0) if not isinstance(hop, dict) else hop.get("delay_seconds", 0.0)

            server_name = by_server or from_server
            if server_name:
                norm_server = self.normalize_domain(server_name)
                server_id = f"mail_server:{norm_server}"
                self._add_entity(
                    entity_id=server_id,
                    entity_type="MailServer",
                    display_label=norm_server,
                    normalized_value=norm_server,
                    evidence_reference=f"email_relay_hops:hop_{hop_num}",
                    properties={
                        "server_name": norm_server,
                        "hop_number": hop_num,
                        "protocol": protocol,
                        "delay_seconds": delay,
                        "is_origin": is_origin,
                        "is_anomaly": is_anomaly,
                    },
                    is_origin=is_origin,
                    is_suspicious=is_anomaly,
                )

            # Hop IP
            if hop_ip:
                norm_ip, version, is_priv = self.normalize_ip(hop_ip)
                if norm_ip:
                    ip_id = f"ip:{norm_ip}"
                    self._add_entity(
                        entity_id=ip_id,
                        entity_type="IPAddress",
                        display_label=norm_ip,
                        normalized_value=norm_ip,
                        evidence_reference=f"email_relay_hops:hop_{hop_num}",
                        properties={
                            "ip": norm_ip,
                            "source": "received_header",
                            "ip_version": version,
                            "is_private": is_priv,
                            "is_origin": is_origin,
                            "hop_number": hop_num,
                        },
                        is_origin=is_origin,
                    )

        # 4. Extracted URLs & Associated Domains
        for url_rec in self.urls:
            raw_url = getattr(url_rec, "original_url", None) or getattr(url_rec, "normalized_url", "") if not isinstance(url_rec, dict) else (url_rec.get("original_url") or url_rec.get("normalized_url", ""))
            u_id = getattr(url_rec, "id", None) if not isinstance(url_rec, dict) else url_rec.get("id")
            u_risk = getattr(url_rec, "risk_score", 0) if not isinstance(url_rec, dict) else url_rec.get("risk_score", 0)
            u_threat = getattr(url_rec, "threat_level", "clean") if not isinstance(url_rec, dict) else url_rec.get("threat_level", "clean")
            is_lookalike = getattr(url_rec, "is_lookalike", False) if not isinstance(url_rec, dict) else url_rec.get("is_lookalike", False)
            is_ip_based = getattr(url_rec, "is_ip_based", False) if not isinstance(url_rec, dict) else url_rec.get("is_ip_based", False)
            is_shortened = getattr(url_rec, "is_shortened", False) if not isinstance(url_rec, dict) else url_rec.get("is_shortened", False)
            reason = getattr(url_rec, "reason", None) if not isinstance(url_rec, dict) else url_rec.get("reason")

            url_hash, norm_url, scheme, hostname, domain = self.normalize_url(raw_url)
            if norm_url:
                url_id = f"url:{url_hash}"
                url_label = norm_url if len(norm_url) <= 45 else f"{norm_url[:42]}..."
                parsed_u = urlparse(norm_url)
                path = parsed_u.path or "/"

                is_suspicious_url = (u_risk or 0) >= 60 or bool(is_lookalike) or bool(is_ip_based) or (u_threat in ("high", "critical"))

                self._add_entity(
                    entity_id=url_id,
                    entity_type="URL",
                    display_label=url_label,
                    normalized_value=norm_url,
                    risk_score=u_risk,
                    severity=u_threat,
                    evidence_reference=f"email_urls:{u_id or url_hash}",
                    properties={
                        "normalized_url": norm_url,
                        "scheme": scheme,
                        "hostname": hostname,
                        "path": path,
                        "is_suspicious": is_suspicious_url,
                        "is_ip_url": bool(is_ip_based),
                        "is_lookalike": bool(is_lookalike),
                        "is_shortened": bool(is_shortened),
                        "threat_level": u_threat,
                        "risk_score": u_risk,
                        "reason": reason,
                    },
                    is_suspicious=is_suspicious_url,
                )

                # Domain of the URL
                if domain:
                    norm_domain = self.normalize_domain(domain)
                    dom_id = f"domain:{norm_domain}"
                    tld = norm_domain.split(".")[-1] if "." in norm_domain else ""
                    is_zero_day = bool(is_lookalike) or (u_risk or 0) >= 60
                    self._add_entity(
                        entity_id=dom_id,
                        entity_type="Domain",
                        display_label=norm_domain,
                        normalized_value=norm_domain,
                        risk_score=u_risk if (is_lookalike or is_zero_day) else None,
                        severity=u_threat if (is_lookalike or is_zero_day) else None,
                        evidence_reference=f"email_urls:{u_id or url_hash}",
                        properties={
                            "domain_name": norm_domain,
                            "is_lookalike": bool(is_lookalike),
                            "is_zero_day": is_zero_day,
                            "tld": tld,
                            "source_url": norm_url,
                        },
                        is_suspicious=bool(is_lookalike or is_zero_day),
                    )

                    # Resolve domain host IP for threat graph synchronization (e.g. 198.51.100.25)
                    from app.services.geo.geo_resolver import geo_resolver
                    resolved_geo = geo_resolver.resolve_ip(norm_domain)
                    if resolved_geo and resolved_geo.ip and not resolved_geo.is_bogon:
                        res_ip_norm, res_v, res_priv = self.normalize_ip(resolved_geo.ip)
                        if res_ip_norm:
                            res_ip_id = f"ip:{res_ip_norm}"
                            self._add_entity(
                                entity_id=res_ip_id,
                                entity_type="IPAddress",
                                display_label=res_ip_norm,
                                normalized_value=res_ip_norm,
                                evidence_reference=f"dns_resolution:{norm_domain}",
                                properties={
                                    "ip": res_ip_norm,
                                    "source": "dns_a_record",
                                    "ip_version": res_v,
                                    "is_private": res_priv,
                                    "as_org": resolved_geo.as_org,
                                    "asn": resolved_geo.asn,
                                    "country": resolved_geo.country_name,
                                    "is_target_host": True,
                                },
                                is_suspicious=True,
                            )

                # If URL hostname is an IP
                if is_ip_based and hostname:
                    ip_norm, version, is_priv = self.normalize_ip(hostname)
                    if ip_norm:
                        ip_id = f"ip:{ip_norm}"
                        self._add_entity(
                            entity_id=ip_id,
                            entity_type="IPAddress",
                            display_label=ip_norm,
                            normalized_value=ip_norm,
                            evidence_reference=f"email_urls:{u_id or url_hash}",
                            properties={
                                "ip": ip_norm,
                                "source": "url_host",
                                "ip_version": version,
                                "is_private": is_priv,
                            },
                        )

        # 5. Extracted IPs & Probable Origin Candidate
        for ip_rec in self.ips:
            raw_ip = getattr(ip_rec, "ip", "") if not isinstance(ip_rec, dict) else ip_rec.get("ip", "")
            ip_id_ref = getattr(ip_rec, "id", "") if not isinstance(ip_rec, dict) else ip_rec.get("id", "")
            ip_src = getattr(ip_rec, "source", "url_host") if not isinstance(ip_rec, dict) else ip_rec.get("source", "url_host")
            ip_conf = getattr(ip_rec, "confidence", 1.0) if not isinstance(ip_rec, dict) else ip_rec.get("confidence", 1.0)
            is_prob_orig = getattr(ip_rec, "is_probable_origin", False) if not isinstance(ip_rec, dict) else ip_rec.get("is_probable_origin", False)

            norm_ip, version, is_priv = self.normalize_ip(raw_ip)
            if norm_ip:
                ip_id = f"ip:{norm_ip}"
                self._add_entity(
                    entity_id=ip_id,
                    entity_type="IPAddress",
                    display_label=norm_ip,
                    normalized_value=norm_ip,
                    evidence_reference=f"email_ips:{ip_id_ref or norm_ip}",
                    properties={
                        "ip": norm_ip,
                        "source": ip_src or "url_host",
                        "ip_version": version,
                        "is_private": is_priv,
                        "confidence": ip_conf,
                        "is_probable_origin": is_prob_orig,
                    },
                    is_origin=is_prob_orig,
                )

        if self.probable_origin_ip:
            orig_ip, version, is_priv = self.normalize_ip(self.probable_origin_ip)
            if orig_ip:
                ip_id = f"ip:{orig_ip}"
                self._add_entity(
                    entity_id=ip_id,
                    entity_type="IPAddress",
                    display_label=orig_ip,
                    normalized_value=orig_ip,
                    evidence_reference="email_analyses:probable_origin_ip",
                    properties={
                        "ip": orig_ip,
                        "source": "received_header",
                        "ip_version": version,
                        "is_private": is_priv,
                        "is_probable_origin": True,
                        "confidence": self.probable_origin_confidence or 0.85,
                        "origin_source": self.probable_origin_source,
                    },
                    is_origin=True,
                )

        # 6. Attachments & Cryptographic Hashes
        for att in self.attachments:
            att_sha = getattr(att, "sha256", "") if not isinstance(att, dict) else att.get("sha256", "")
            att_name = getattr(att, "filename", "attachment") if not isinstance(att, dict) else att.get("filename", "attachment")
            att_id_ref = getattr(att, "id", None) if not isinstance(att, dict) else att.get("id")
            att_type = getattr(att, "content_type", "application/octet-stream") if not isinstance(att, dict) else att.get("content_type", "application/octet-stream")
            att_size = getattr(att, "size_bytes", 0) or getattr(att, "size", 0) if not isinstance(att, dict) else (att.get("size_bytes") or att.get("size", 0))
            is_exec = getattr(att, "is_executable", False) if not isinstance(att, dict) else att.get("is_executable", False)
            is_susp = getattr(att, "is_suspicious", False) if not isinstance(att, dict) else att.get("is_suspicious", False)
            is_dbl = getattr(att, "is_double_extension", False) if not isinstance(att, dict) else att.get("is_double_extension", False)
            signals = getattr(att, "detected_signals", []) if not isinstance(att, dict) else att.get("detected_signals", [])

            norm_sha = self.normalize_hash(att_sha)
            if not norm_sha:
                norm_sha = hashlib.sha256((att_name or "unknown").encode("utf-8")).hexdigest()

            att_id = f"attachment:{norm_sha}"
            att_label = att_name or "attachment"
            suspicious_att = bool(is_susp) or bool(is_exec) or bool(is_dbl)

            self._add_entity(
                entity_id=att_id,
                entity_type="Attachment",
                display_label=att_label,
                normalized_value=att_name,
                evidence_reference=f"email_attachments:{att_id_ref or norm_sha}",
                properties={
                    "sha256": norm_sha,
                    "filename": att_name,
                    "content_type": att_type,
                    "size": att_size,
                    "size_bytes": att_size,
                    "is_suspicious": suspicious_att,
                    "is_executable": bool(is_exec),
                    "is_double_extension": bool(is_dbl),
                    "detected_signals": signals or [],
                },
                is_suspicious=suspicious_att,
            )

            # Cryptographic FileHash Node
            hash_id = f"file_hash:{norm_sha}"
            self._add_entity(
                entity_id=hash_id,
                entity_type="FileHash",
                display_label=f"{norm_sha[:16]}...",
                normalized_value=norm_sha,
                evidence_reference=f"email_attachments:{att_id_ref or norm_sha}",
                properties={
                    "sha256": norm_sha,
                    "algorithm": "sha256",
                },
                is_suspicious=suspicious_att,
            )

        return list(self._entities.values())

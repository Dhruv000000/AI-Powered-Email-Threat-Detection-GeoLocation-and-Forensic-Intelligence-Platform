import hashlib
import ipaddress
import re
from typing import Dict, Any, List, Tuple, Optional, Set
from urllib.parse import urlparse, unquote

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


class EntityBuilder:
    """
    Forensic Entity Builder.
    Transforms Task 01 structured email evidence into normalized, deduplicated graph entity nodes
    with deterministic identifiers and rich evidentiary provenance.
    Strictly static analysis with zero live network or DNS egress.
    """

    def __init__(self, analysis: EmailAnalysisModel, investigation_id: str):
        self.analysis = analysis
        self.analysis_id = analysis.analysis_id
        self.investigation_id = investigation_id
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
        if entity_id in self._entities:
            existing = self._entities[entity_id]
            # Retain highest risk score
            if risk_score is not None:
                if existing.get("risk_score") is None or risk_score > existing.get("risk_score", 0):
                    existing["risk_score"] = risk_score
                    existing["severity"] = severity
            if is_origin:
                existing["is_origin"] = True
            if is_suspicious:
                existing["is_suspicious"] = True
            if properties:
                existing.setdefault("properties", {}).update(properties)
            return existing

        entity = {
            "id": entity_id,
            "investigation_id": self.investigation_id,
            "type": entity_type,
            "label": display_label,
            "display_label": display_label,
            "normalized_value": normalized_value,
            "risk_score": risk_score,
            "severity": severity or ("high" if (risk_score or 0) >= 70 else "medium" if (risk_score or 0) >= 40 else "low"),
            "evidence_reference": evidence_reference,
            "is_origin": is_origin,
            "is_suspicious": is_suspicious,
            "properties": properties or {},
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
        meta = self.analysis.metadata_record
        subject_preview = (meta.subject if meta and meta.subject else "No Subject")[:60]
        self._add_entity(
            entity_id=email_id,
            entity_type="Email",
            display_label=f"Email: {subject_preview}",
            normalized_value=self.analysis_id,
            risk_score=self.analysis.risk_score,
            severity=self.analysis.severity,
            evidence_reference=f"email_analyses:{self.analysis_id}",
            properties={
                "analysis_id": self.analysis_id,
                "message_id": meta.message_id if meta else None,
                "threat_type": self.analysis.threat_type,
                "risk_score": self.analysis.risk_score,
                "severity": self.analysis.severity,
                "ai_confidence": self.analysis.ai_confidence,
                "filename": self.analysis.filename,
                "sha256": self.analysis.sha256,
            },
            is_suspicious=(self.analysis.risk_score or 0) >= 60,
        )

        # 2. Sender, Recipients & Domains
        if meta:
            # From Address
            if meta.from_email or meta.from_header:
                raw_from = meta.from_header or meta.from_email or ""
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
                        properties={"role": "sender", "domain": norm_domain},
                    )

                    # Sender Domain
                    if norm_domain:
                        dom_id = f"domain:{norm_domain}"
                        self._add_entity(
                            entity_id=dom_id,
                            entity_type="Domain",
                            display_label=norm_domain,
                            normalized_value=norm_domain,
                            evidence_reference="email_metadata:from_domain",
                            properties={"role": "sender_domain"},
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
            if meta.reply_to:
                rt_norm, rt_domain, _ = self.normalize_email_address(meta.reply_to)
                if rt_norm:
                    rt_hash = hashlib.sha256(rt_norm.encode("utf-8")).hexdigest()[:16]
                    rt_id = f"email_address:{rt_hash}"
                    self._add_entity(
                        entity_id=rt_id,
                        entity_type="EmailAddress",
                        display_label=rt_norm,
                        normalized_value=rt_norm,
                        evidence_reference="email_metadata:reply_to",
                        properties={"role": "reply_to", "domain": rt_domain},
                        is_suspicious=True,
                    )
                    if rt_domain:
                        rt_dom_id = f"domain:{rt_domain}"
                        self._add_entity(
                            entity_id=rt_dom_id,
                            entity_type="Domain",
                            display_label=rt_domain,
                            normalized_value=rt_domain,
                            evidence_reference="email_metadata:reply_to",
                            properties={"role": "reply_to_domain"},
                        )

            # To Recipients
            if meta.to_recipients and isinstance(meta.to_recipients, list):
                for raw_to in meta.to_recipients:
                    t_norm, t_domain, _ = self.normalize_email_address(str(raw_to))
                    if t_norm:
                        t_hash = hashlib.sha256(t_norm.encode("utf-8")).hexdigest()[:16]
                        t_id = f"email_address:{t_hash}"
                        self._add_entity(
                            entity_id=t_id,
                            entity_type="EmailAddress",
                            display_label=t_norm,
                            normalized_value=t_norm,
                            evidence_reference="email_metadata:to_recipients",
                            properties={"role": "recipient", "domain": t_domain},
                        )

        # 3. Relay Hops & Mail Servers
        for hop in self.analysis.relay_hops:
            server_name = hop.by_server or hop.from_server
            if server_name:
                norm_server = self.normalize_domain(server_name)
                server_id = f"mail_server:{norm_server}"
                self._add_entity(
                    entity_id=server_id,
                    entity_type="MailServer",
                    display_label=norm_server,
                    normalized_value=norm_server,
                    evidence_reference=f"email_relay_hops:hop_{hop.hop_number}",
                    properties={
                        "hop_number": hop.hop_number,
                        "protocol": hop.protocol,
                        "delay_seconds": hop.delay_seconds,
                        "is_origin": hop.is_origin_node,
                        "is_anomaly": hop.is_anomaly,
                    },
                    is_origin=hop.is_origin_node,
                    is_suspicious=hop.is_anomaly,
                )

            # Hop IP
            if hop.ip:
                norm_ip, version, is_priv = self.normalize_ip(hop.ip)
                if norm_ip:
                    ip_id = f"ip:{norm_ip}"
                    self._add_entity(
                        entity_id=ip_id,
                        entity_type="IP",
                        display_label=norm_ip,
                        normalized_value=norm_ip,
                        evidence_reference=f"email_relay_hops:hop_{hop.hop_number}",
                        properties={
                            "ip_version": version,
                            "is_private": is_priv,
                            "is_origin": hop.is_origin_node,
                            "hop_number": hop.hop_number,
                        },
                        is_origin=hop.is_origin_node,
                    )

        # 4. Extracted URLs & Associated Domains
        for url_rec in self.analysis.urls:
            url_hash, norm_url, scheme, hostname, domain = self.normalize_url(url_rec.original_url or url_rec.normalized_url)
            if norm_url:
                url_id = f"url:{url_hash}"
                url_label = norm_url if len(norm_url) <= 45 else f"{norm_url[:42]}..."
                self._add_entity(
                    entity_id=url_id,
                    entity_type="URL",
                    display_label=url_label,
                    normalized_value=norm_url,
                    risk_score=url_rec.risk_score,
                    severity=url_rec.threat_level,
                    evidence_reference=f"email_urls:{url_rec.id}",
                    properties={
                        "scheme": scheme,
                        "hostname": hostname,
                        "domain": domain,
                        "is_lookalike": bool(url_rec.is_lookalike),
                        "is_ip_based": bool(url_rec.is_ip_based),
                        "is_shortened": bool(url_rec.is_shortened),
                        "threat_level": url_rec.threat_level or "clean",
                        "risk_score": url_rec.risk_score or 0,
                        "reason": url_rec.reason,
                    },
                    is_suspicious=(url_rec.risk_score or 0) >= 60 or bool(url_rec.is_lookalike),
                )

                # Domain of the URL
                if domain:
                    norm_domain = self.normalize_domain(domain)
                    dom_id = f"domain:{norm_domain}"
                    self._add_entity(
                        entity_id=dom_id,
                        entity_type="Domain",
                        display_label=norm_domain,
                        normalized_value=norm_domain,
                        risk_score=url_rec.risk_score if url_rec.is_lookalike else None,
                        severity=url_rec.threat_level if url_rec.is_lookalike else None,
                        evidence_reference=f"email_urls:{url_rec.id}",
                        properties={
                            "is_lookalike": bool(url_rec.is_lookalike),
                            "source_url": norm_url,
                        },
                        is_suspicious=bool(url_rec.is_lookalike),
                    )

        # 5. Extracted IPs & Probable Origin Candidate
        for ip_rec in self.analysis.ips:
            norm_ip, version, is_priv = self.normalize_ip(ip_rec.ip)
            if norm_ip:
                ip_id = f"ip:{norm_ip}"
                self._add_entity(
                    entity_id=ip_id,
                    entity_type="IP",
                    display_label=norm_ip,
                    normalized_value=norm_ip,
                    evidence_reference=f"email_ips:{ip_rec.id}",
                    properties={
                        "ip_version": version,
                        "is_private": is_priv,
                        "source": ip_rec.source,
                        "confidence": ip_rec.confidence,
                        "is_probable_origin": ip_rec.is_probable_origin,
                    },
                    is_origin=ip_rec.is_probable_origin,
                )

        if self.analysis.probable_origin_ip:
            orig_ip, version, is_priv = self.normalize_ip(self.analysis.probable_origin_ip)
            if orig_ip:
                ip_id = f"ip:{orig_ip}"
                self._add_entity(
                    entity_id=ip_id,
                    entity_type="IP",
                    display_label=orig_ip,
                    normalized_value=orig_ip,
                    evidence_reference="email_analyses:probable_origin_ip",
                    properties={
                        "ip_version": version,
                        "is_private": is_priv,
                        "is_probable_origin": True,
                        "confidence": self.analysis.probable_origin_confidence or 0.85,
                        "source": self.analysis.probable_origin_source,
                    },
                    is_origin=True,
                )

        # 6. Attachments & Cryptographic Hashes
        for att in self.analysis.attachments:
            norm_sha = self.normalize_hash(att.sha256)
            att_id = f"attachment:{norm_sha}"
            att_label = att.filename or "attachment"
            self._add_entity(
                entity_id=att_id,
                entity_type="Attachment",
                display_label=att_label,
                normalized_value=att.filename,
                evidence_reference=f"email_attachments:{att.id}",
                properties={
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size_bytes": att.size_bytes or 0,
                    "sha256": norm_sha,
                    "is_executable": bool(att.is_executable),
                    "is_suspicious": bool(att.is_suspicious),
                    "is_double_extension": bool(att.is_double_extension),
                    "detected_signals": att.detected_signals or [],
                },
                is_suspicious=bool(att.is_suspicious) or bool(att.is_executable) or bool(att.is_double_extension),
            )

            # Cryptographic FileHash Node
            if norm_sha:
                hash_id = f"file_hash:{norm_sha}"
                self._add_entity(
                    entity_id=hash_id,
                    entity_type="FileHash",
                    display_label=f"{norm_sha[:16]}...",
                    normalized_value=norm_sha,
                    evidence_reference=f"email_attachments:{att.id}",
                    properties={
                        "sha256": norm_sha,
                        "algorithm": "sha256",
                    },
                    is_suspicious=bool(att.is_suspicious) or bool(att.is_executable),
                )

        return list(self._entities.values())

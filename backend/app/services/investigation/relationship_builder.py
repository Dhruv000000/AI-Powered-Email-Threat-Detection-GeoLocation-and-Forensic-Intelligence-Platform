import hashlib
from typing import Dict, Any, List, Optional
from app.db.models.email_analysis import EmailAnalysisModel
from app.services.investigation.entity_builder import EntityBuilder


class RelationshipBuilder:
    """
    Forensic Relationship Builder.
    Generates typed relationships with explicit provenance linking all entities
    extracted from Task 01 structured records.
    """

    def __init__(
        self,
        analysis: EmailAnalysisModel,
        investigation_id: str,
        entities: List[Dict[str, Any]],
    ):
        self.analysis = analysis
        self.analysis_id = analysis.analysis_id
        self.investigation_id = investigation_id
        self.entities = entities
        self.entity_ids = {e["id"]: e for e in entities}
        self._relationships: Dict[str, Dict[str, Any]] = {}

    def _generate_rel_id(self, source_id: str, rel_type: str, target_id: str) -> str:
        raw_key = f"{source_id}->{rel_type}->{target_id}"
        hash_val = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        return f"rel:{hash_val}"

    def _add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        provenance_source: str,
        source_reference: Optional[str] = None,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Add relationship ensuring both source and target nodes exist in the entity map."""
        if source_id not in self.entity_ids or target_id not in self.entity_ids:
            return None

        rel_id = self._generate_rel_id(source_id, rel_type, target_id)
        if rel_id in self._relationships:
            return self._relationships[rel_id]

        rel = {
            "id": rel_id,
            "investigation_id": self.investigation_id,
            "source_id": source_id,
            "target_id": target_id,
            "type": rel_type,
            "provenance": provenance_source,
            "source_reference": source_reference,
            "confidence": confidence,
            "properties": properties or {},
        }
        self._relationships[rel_id] = rel
        return rel

    def build_all_relationships(self) -> List[Dict[str, Any]]:
        self._relationships.clear()
        email_id = f"email:{self.analysis_id}"
        meta = self.analysis.metadata_record

        # 1. Sender & Recipient Relationships
        if meta:
            # Sender Address -> SENT -> Email
            if meta.from_header or meta.from_email:
                raw_from = meta.from_header or meta.from_email or ""
                norm_email, norm_domain, display_name = EntityBuilder.normalize_email_address(raw_from)
                if norm_email:
                    addr_hash = hashlib.sha256(norm_email.encode("utf-8")).hexdigest()[:16]
                    addr_id = f"email_address:{addr_hash}"

                    self._add_relationship(
                        source_id=addr_id,
                        target_id=email_id,
                        rel_type="SENT",
                        provenance_source="email_header",
                        source_reference="email_metadata:from_header",
                        confidence=1.0,
                    )

                    # Sender Address -> USES_DOMAIN -> Domain
                    if norm_domain:
                        dom_id = f"domain:{norm_domain}"
                        self._add_relationship(
                            source_id=addr_id,
                            target_id=dom_id,
                            rel_type="USES_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:from_domain",
                            confidence=1.0,
                        )

                    # Person -> SENT / ASSOCIATED_WITH -> EmailAddress
                    if display_name:
                        person_hash = hashlib.sha256(display_name.lower().encode("utf-8")).hexdigest()[:16]
                        person_id = f"person:{person_hash}"
                        self._add_relationship(
                            source_id=person_id,
                            target_id=addr_id,
                            rel_type="ASSOCIATED_WITH",
                            provenance_source="email_header",
                            source_reference="email_metadata:from_display_name",
                            confidence=0.9,
                        )

            # Email -> REPLIED_TO -> ReplyTo Address
            if meta.reply_to:
                rt_norm, rt_domain, _ = EntityBuilder.normalize_email_address(meta.reply_to)
                if rt_norm:
                    rt_hash = hashlib.sha256(rt_norm.encode("utf-8")).hexdigest()[:16]
                    rt_id = f"email_address:{rt_hash}"
                    self._add_relationship(
                        source_id=email_id,
                        target_id=rt_id,
                        rel_type="REPLIED_TO",
                        provenance_source="reply_to",
                        source_reference="email_metadata:reply_to",
                        confidence=1.0,
                    )

                    if rt_domain:
                        rt_dom_id = f"domain:{rt_domain}"
                        self._add_relationship(
                            source_id=rt_id,
                            target_id=rt_dom_id,
                            rel_type="USES_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:reply_to",
                            confidence=1.0,
                        )

            # Email -> DELIVERED_TO -> Recipient Address
            if meta.to_recipients and isinstance(meta.to_recipients, list):
                for raw_to in meta.to_recipients:
                    t_norm, t_domain, _ = EntityBuilder.normalize_email_address(str(raw_to))
                    if t_norm:
                        t_hash = hashlib.sha256(t_norm.encode("utf-8")).hexdigest()[:16]
                        t_id = f"email_address:{t_hash}"
                        self._add_relationship(
                            source_id=email_id,
                            target_id=t_id,
                            rel_type="DELIVERED_TO",
                            provenance_source="email_header",
                            source_reference="email_metadata:to_recipients",
                            confidence=1.0,
                        )
                        if t_domain:
                            t_dom_id = f"domain:{t_domain}"
                            self._add_relationship(
                                source_id=t_id,
                                target_id=t_dom_id,
                                rel_type="USES_DOMAIN",
                                provenance_source="forensic_rule",
                                source_reference="email_metadata:to_recipients",
                                confidence=1.0,
                            )

        # 2. Relay Hops & Infrastructure
        for hop in self.analysis.relay_hops:
            server_name = hop.by_server or hop.from_server
            server_id = None
            if server_name:
                norm_server = EntityBuilder.normalize_domain(server_name)
                server_id = f"mail_server:{norm_server}"

                # Email -> OBSERVED_VIA -> MailServer
                self._add_relationship(
                    source_id=email_id,
                    target_id=server_id,
                    rel_type="OBSERVED_VIA",
                    provenance_source="received_header",
                    source_reference=f"email_relay_hops:hop_{hop.hop_number}",
                    confidence=0.95,
                    properties={"hop_number": hop.hop_number, "is_origin": hop.is_origin_node},
                )

            # Hop IP
            if hop.ip:
                norm_ip, _, _ = EntityBuilder.normalize_ip(hop.ip)
                if norm_ip:
                    ip_id = f"ip:{norm_ip}"
                    if server_id:
                        # MailServer -> HAS_IP -> IP
                        self._add_relationship(
                            source_id=server_id,
                            target_id=ip_id,
                            rel_type="HAS_IP",
                            provenance_source="received_header",
                            source_reference=f"email_relay_hops:hop_{hop.hop_number}",
                            confidence=0.95,
                        )
                    else:
                        # Fallback direct: Email -> OBSERVED_VIA -> IP
                        self._add_relationship(
                            source_id=email_id,
                            target_id=ip_id,
                            rel_type="OBSERVED_VIA",
                            provenance_source="received_header",
                            source_reference=f"email_relay_hops:hop_{hop.hop_number}",
                            confidence=0.9,
                        )

        # 3. Probable Origin IP
        if self.analysis.probable_origin_ip:
            orig_ip, _, _ = EntityBuilder.normalize_ip(self.analysis.probable_origin_ip)
            if orig_ip:
                ip_id = f"ip:{orig_ip}"
                self._add_relationship(
                    source_id=email_id,
                    target_id=ip_id,
                    rel_type="HOSTED_ON",
                    provenance_source="forensic_rule",
                    source_reference="email_analyses:probable_origin_ip",
                    confidence=self.analysis.probable_origin_confidence or 0.85,
                    properties={"role": "probable_origin_candidate"},
                )

        # 4. URLs & Domains
        for url_rec in self.analysis.urls:
            url_hash, norm_url, _, _, domain = EntityBuilder.normalize_url(url_rec.original_url or url_rec.normalized_url)
            if norm_url:
                url_id = f"url:{url_hash}"

                # Email -> LINKS_TO -> URL
                self._add_relationship(
                    source_id=email_id,
                    target_id=url_id,
                    rel_type="LINKS_TO",
                    provenance_source="email_body",
                    source_reference=f"email_urls:{url_rec.id}",
                    confidence=1.0,
                )

                # URL -> USES_DOMAIN -> Domain
                if domain:
                    norm_domain = EntityBuilder.normalize_domain(domain)
                    dom_id = f"domain:{norm_domain}"
                    self._add_relationship(
                        source_id=url_id,
                        target_id=dom_id,
                        rel_type="USES_DOMAIN",
                        provenance_source="forensic_rule",
                        source_reference=f"email_urls:{url_rec.id}",
                        confidence=1.0,
                    )

                    # If URL was IP based, link Domain/URL -> HOSTED_ON -> IP
                    if url_rec.is_ip_based:
                        ip_norm, _, _ = EntityBuilder.normalize_ip(norm_domain)
                        if ip_norm:
                            ip_id = f"ip:{ip_norm}"
                            self._add_relationship(
                                source_id=url_id,
                                target_id=ip_id,
                                rel_type="HOSTED_ON",
                                provenance_source="forensic_rule",
                                source_reference=f"email_urls:{url_rec.id}",
                                confidence=1.0,
                            )

        # 5. Attachments & Hashes
        for att in self.analysis.attachments:
            norm_sha = EntityBuilder.normalize_hash(att.sha256)
            if norm_sha:
                att_id = f"attachment:{norm_sha}"
                hash_id = f"file_hash:{norm_sha}"

                # Email -> HAS_ATTACHMENT -> Attachment
                self._add_relationship(
                    source_id=email_id,
                    target_id=att_id,
                    rel_type="HAS_ATTACHMENT",
                    provenance_source="attachment",
                    source_reference=f"email_attachments:{att.id}",
                    confidence=1.0,
                )

                # Attachment -> HAS_HASH -> FileHash
                self._add_relationship(
                    source_id=att_id,
                    target_id=hash_id,
                    rel_type="HAS_HASH",
                    provenance_source="forensic_rule",
                    source_reference=f"email_attachments:{att.id}",
                    confidence=1.0,
                )

        return list(self._relationships.values())

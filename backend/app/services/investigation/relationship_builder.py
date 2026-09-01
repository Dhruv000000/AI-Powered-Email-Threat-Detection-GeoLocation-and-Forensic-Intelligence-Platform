import hashlib
from typing import Dict, Any, List, Optional, Union
from app.db.models.email_analysis import EmailAnalysisModel
from app.schemas.email_analysis import EmailAnalysisResponse
from app.services.investigation.entity_builder import EntityBuilder


class RelationshipBuilder:
    """
    Forensic Relationship Builder.
    Generates typed directed relationships with explicit provenance linking all entities
    extracted from Task 01 structured records.
    """

    def __init__(
        self,
        analysis: Union[EmailAnalysisModel, EmailAnalysisResponse, Dict[str, Any]],
        investigation_id: str,
        entities: List[Dict[str, Any]],
    ):
        self.analysis = analysis
        if isinstance(analysis, dict):
            self.analysis_id = analysis.get("analysis_id", "ANL-UNKNOWN")
            self.metadata_obj = analysis.get("metadata") or analysis.get("metadata_record")
            self.relay_hops = analysis.get("relay_hops") or []
            self.urls = analysis.get("extracted_urls") or analysis.get("urls") or []
            self.attachments = analysis.get("attachments") or []
            self.probable_origin_ip = analysis.get("probable_origin_ip")
            self.probable_origin_confidence = analysis.get("probable_origin_confidence")
        else:
            self.analysis_id = getattr(analysis, "analysis_id", "ANL-UNKNOWN")
            self.metadata_obj = getattr(analysis, "metadata_record", None) or getattr(analysis, "metadata", None)
            self.relay_hops = getattr(analysis, "relay_hops", []) or []
            self.urls = getattr(analysis, "urls", None) or getattr(analysis, "extracted_urls", []) or []
            self.attachments = getattr(analysis, "attachments", []) or []
            self.probable_origin_ip = getattr(analysis, "probable_origin_ip", None)
            self.probable_origin_confidence = getattr(analysis, "probable_origin_confidence", None)

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

        props = dict(properties or {})
        props["investigation_id"] = self.investigation_id
        props["analysis_id"] = self.analysis_id

        rel = {
            "id": rel_id,
            "investigation_id": self.investigation_id,
            "analysis_id": self.analysis_id,
            "source_id": source_id,
            "target_id": target_id,
            "source": source_id,
            "target": target_id,
            "type": rel_type,
            "label": rel_type,
            "provenance": provenance_source,
            "source_reference": source_reference,
            "confidence": float(confidence),
            "properties": props,
        }
        self._relationships[rel_id] = rel
        return rel

    def build_all_relationships(self) -> List[Dict[str, Any]]:
        self._relationships.clear()
        email_id = f"email:{self.analysis_id}"
        meta = self.metadata_obj

        # Extract metadata fields
        from_header = None
        from_email = None
        reply_to = None
        to_recipients = []

        if meta:
            if isinstance(meta, dict):
                from_header = meta.get("from_header")
                from_email = meta.get("from_email") or meta.get("sender")
                reply_to = meta.get("reply_to")
                to_recipients = meta.get("to_recipients") or meta.get("recipients") or []
            else:
                from_header = getattr(meta, "from_header", None)
                from_email = getattr(meta, "from_email", None)
                reply_to = getattr(meta, "reply_to", None)
                to_recipients = getattr(meta, "to_recipients", []) or []

        # 1. Sender & Recipient Relationships
        if meta:
            # (:EmailAddress)-[:SENT {source: "header_from"}]->(:Email)
            raw_from = from_header or from_email or ""
            if raw_from:
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
                        properties={"source": "header_from"},
                    )

                    # (:EmailAddress)-[:BELONGS_TO_DOMAIN]->(:Domain)
                    if norm_domain:
                        dom_id = f"domain:{norm_domain}"
                        self._add_relationship(
                            source_id=addr_id,
                            target_id=dom_id,
                            rel_type="BELONGS_TO_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:from_domain",
                            confidence=1.0,
                        )
                        # Alias for compatibility
                        self._add_relationship(
                            source_id=addr_id,
                            target_id=dom_id,
                            rel_type="USES_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:from_domain",
                            confidence=1.0,
                        )

                    # (:Person)-[:ASSOCIATED_WITH]->(:EmailAddress)
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

            # (:EmailAddress)-[:SPECIFIED_AS_REPLY_TO]->(:Email) and (:Email)-[:REPLIED_TO]->(:EmailAddress)
            if reply_to:
                rt_norm, rt_domain, _ = EntityBuilder.normalize_email_address(reply_to)
                if rt_norm:
                    rt_hash = hashlib.sha256(rt_norm.encode("utf-8")).hexdigest()[:16]
                    rt_id = f"email_address:{rt_hash}"
                    
                    self._add_relationship(
                        source_id=rt_id,
                        target_id=email_id,
                        rel_type="SPECIFIED_AS_REPLY_TO",
                        provenance_source="reply_to",
                        source_reference="email_metadata:reply_to",
                        confidence=1.0,
                    )
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
                            rel_type="BELONGS_TO_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:reply_to",
                            confidence=1.0,
                        )
                        self._add_relationship(
                            source_id=rt_id,
                            target_id=rt_dom_id,
                            rel_type="USES_DOMAIN",
                            provenance_source="forensic_rule",
                            source_reference="email_metadata:reply_to",
                            confidence=1.0,
                        )

            # (:Email)-[:ADDRESSED_TO]->(:EmailAddress) and (:Email)-[:DELIVERED_TO]->(:EmailAddress)
            if to_recipients and isinstance(to_recipients, list):
                for raw_to in to_recipients:
                    t_norm, t_domain, _ = EntityBuilder.normalize_email_address(str(raw_to))
                    if t_norm:
                        t_hash = hashlib.sha256(t_norm.encode("utf-8")).hexdigest()[:16]
                        t_id = f"email_address:{t_hash}"
                        self._add_relationship(
                            source_id=email_id,
                            target_id=t_id,
                            rel_type="ADDRESSED_TO",
                            provenance_source="email_header",
                            source_reference="email_metadata:to_recipients",
                            confidence=1.0,
                        )
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
                                rel_type="BELONGS_TO_DOMAIN",
                                provenance_source="forensic_rule",
                                source_reference="email_metadata:to_recipients",
                                confidence=1.0,
                            )
                            self._add_relationship(
                                source_id=t_id,
                                target_id=t_dom_id,
                                rel_type="USES_DOMAIN",
                                provenance_source="forensic_rule",
                                source_reference="email_metadata:to_recipients",
                                confidence=1.0,
                            )

        # 2. Relay Hops & Infrastructure
        for hop in self.relay_hops:
            server_name = (
                getattr(hop, "by_server", None) or getattr(hop, "from_server", None)
                if not isinstance(hop, dict) else (hop.get("by_server") or hop.get("from_server"))
            )
            hop_ip = getattr(hop, "ip", None) if not isinstance(hop, dict) else hop.get("ip")
            hop_num = getattr(hop, "hop_number", 1) if not isinstance(hop, dict) else hop.get("hop_number", 1)
            is_origin = getattr(hop, "is_origin_node", False) if not isinstance(hop, dict) else hop.get("is_origin_node", False)

            server_id = None
            if server_name:
                norm_server = EntityBuilder.normalize_domain(server_name)
                server_id = f"mail_server:{norm_server}"

                # (:Email)-[:OBSERVED_VIA]->(:MailServer)
                self._add_relationship(
                    source_id=email_id,
                    target_id=server_id,
                    rel_type="OBSERVED_VIA",
                    provenance_source="received_header",
                    source_reference=f"email_relay_hops:hop_{hop_num}",
                    confidence=0.95,
                    properties={"hop_number": hop_num, "is_origin": is_origin},
                )

            # Hop IP
            if hop_ip:
                norm_ip, _, _ = EntityBuilder.normalize_ip(hop_ip)
                if norm_ip:
                    ip_id = f"ip:{norm_ip}"
                    
                    # (:Email)-[:RELAYED_THROUGH {hop_index: int}]->(:IPAddress)
                    self._add_relationship(
                        source_id=email_id,
                        target_id=ip_id,
                        rel_type="RELAYED_THROUGH",
                        provenance_source="received_header",
                        source_reference=f"email_relay_hops:hop_{hop_num}",
                        confidence=0.95,
                        properties={"hop_index": hop_num, "is_origin": is_origin},
                    )

                    if server_id:
                        # (:MailServer)-[:HAS_IP]->(:IPAddress)
                        self._add_relationship(
                            source_id=server_id,
                            target_id=ip_id,
                            rel_type="HAS_IP",
                            provenance_source="received_header",
                            source_reference=f"email_relay_hops:hop_{hop_num}",
                            confidence=0.95,
                        )
                    else:
                        self._add_relationship(
                            source_id=email_id,
                            target_id=ip_id,
                            rel_type="OBSERVED_VIA",
                            provenance_source="received_header",
                            source_reference=f"email_relay_hops:hop_{hop_num}",
                            confidence=0.9,
                        )

        # 3. Probable Origin IP
        if self.probable_origin_ip:
            orig_ip, _, _ = EntityBuilder.normalize_ip(self.probable_origin_ip)
            if orig_ip:
                ip_id = f"ip:{orig_ip}"
                self._add_relationship(
                    source_id=email_id,
                    target_id=ip_id,
                    rel_type="HOSTED_ON",
                    provenance_source="forensic_rule",
                    source_reference="email_analyses:probable_origin_ip",
                    confidence=self.probable_origin_confidence or 0.85,
                    properties={"role": "probable_origin_candidate"},
                )
                self._add_relationship(
                    source_id=email_id,
                    target_id=ip_id,
                    rel_type="RELAYED_THROUGH",
                    provenance_source="forensic_rule",
                    source_reference="email_analyses:probable_origin_ip",
                    confidence=self.probable_origin_confidence or 0.85,
                    properties={"role": "probable_origin_candidate", "hop_index": 0},
                )

        # 4. URLs & Domains
        for url_rec in self.urls:
            raw_url = (
                getattr(url_rec, "original_url", None) or getattr(url_rec, "normalized_url", "")
                if not isinstance(url_rec, dict) else (url_rec.get("original_url") or url_rec.get("normalized_url", ""))
            )
            u_id = getattr(url_rec, "id", None) if not isinstance(url_rec, dict) else url_rec.get("id")
            is_ip_based = getattr(url_rec, "is_ip_based", False) if not isinstance(url_rec, dict) else url_rec.get("is_ip_based", False)

            url_hash, norm_url, _, hostname, domain = EntityBuilder.normalize_url(raw_url)
            if norm_url:
                url_id = f"url:{url_hash}"

                # (:Email)-[:CONTAINS_URL]->(:URL) and (:Email)-[:LINKS_TO]->(:URL)
                self._add_relationship(
                    source_id=email_id,
                    target_id=url_id,
                    rel_type="CONTAINS_URL",
                    provenance_source="email_body",
                    source_reference=f"email_urls:{u_id or url_hash}",
                    confidence=1.0,
                )
                self._add_relationship(
                    source_id=email_id,
                    target_id=url_id,
                    rel_type="LINKS_TO",
                    provenance_source="email_body",
                    source_reference=f"email_urls:{u_id or url_hash}",
                    confidence=1.0,
                )

                # (:URL)-[:HOSTED_ON_DOMAIN]->(:Domain) and (:URL)-[:USES_DOMAIN]->(:Domain)
                if domain:
                    norm_domain = EntityBuilder.normalize_domain(domain)
                    dom_id = f"domain:{norm_domain}"
                    self._add_relationship(
                        source_id=url_id,
                        target_id=dom_id,
                        rel_type="HOSTED_ON_DOMAIN",
                        provenance_source="forensic_rule",
                        source_reference=f"email_urls:{u_id or url_hash}",
                        confidence=1.0,
                    )
                    self._add_relationship(
                        source_id=url_id,
                        target_id=dom_id,
                        rel_type="USES_DOMAIN",
                        provenance_source="forensic_rule",
                        source_reference=f"email_urls:{u_id or url_hash}",
                        confidence=1.0,
                    )

                # If URL hostname is IP: (:URL)-[:POINTS_TO_IP]->(:IPAddress)
                if is_ip_based and hostname:
                    ip_norm, _, _ = EntityBuilder.normalize_ip(hostname)
                    if ip_norm:
                        ip_id = f"ip:{ip_norm}"
                        self._add_relationship(
                            source_id=url_id,
                            target_id=ip_id,
                            rel_type="POINTS_TO_IP",
                            provenance_source="forensic_rule",
                            source_reference=f"email_urls:{u_id or url_hash}",
                            confidence=1.0,
                        )
                        self._add_relationship(
                            source_id=url_id,
                            target_id=ip_id,
                            rel_type="HOSTED_ON",
                            provenance_source="forensic_rule",
                            source_reference=f"email_urls:{u_id or url_hash}",
                            confidence=1.0,
                        )

        # 5. Attachments & Hashes
        for att in self.attachments:
            att_sha = getattr(att, "sha256", "") if not isinstance(att, dict) else att.get("sha256", "")
            att_name = getattr(att, "filename", "attachment") if not isinstance(att, dict) else att.get("filename", "attachment")
            att_id_ref = getattr(att, "id", None) if not isinstance(att, dict) else att.get("id")

            norm_sha = EntityBuilder.normalize_hash(att_sha)
            if not norm_sha:
                norm_sha = hashlib.sha256((att_name or "unknown").encode("utf-8")).hexdigest()

            att_id = f"attachment:{norm_sha}"
            hash_id = f"file_hash:{norm_sha}"

            # (:Email)-[:ATTACHED]->(:Attachment) and (:Email)-[:HAS_ATTACHMENT]->(:Attachment)
            self._add_relationship(
                source_id=email_id,
                target_id=att_id,
                rel_type="ATTACHED",
                provenance_source="attachment",
                source_reference=f"email_attachments:{att_id_ref or norm_sha}",
                confidence=1.0,
            )
            self._add_relationship(
                source_id=email_id,
                target_id=att_id,
                rel_type="HAS_ATTACHMENT",
                provenance_source="attachment",
                source_reference=f"email_attachments:{att_id_ref or norm_sha}",
                confidence=1.0,
            )

            # (:Attachment)-[:HAS_HASH]->(:FileHash)
            self._add_relationship(
                source_id=att_id,
                target_id=hash_id,
                rel_type="HAS_HASH",
                provenance_source="forensic_rule",
                source_reference=f"email_attachments:{att_id_ref or norm_sha}",
                confidence=1.0,
            )

        return list(self._relationships.values())

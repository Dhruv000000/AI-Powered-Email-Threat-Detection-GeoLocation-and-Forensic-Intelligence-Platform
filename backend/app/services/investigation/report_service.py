import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import select
from fastapi import HTTPException, status

from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailAuthenticationModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)
from app.db.models.investigation import (
    InvestigationModel,
    InvestigationFindingModel,
)
from app.schemas.report import (
    DFIRReportDTO,
    MitreTechniqueDTO,
    RemediationActionDTO,
    IoCItemDTO,
    ExecutiveSummaryDTO,
)
from app.services.investigation.threat_map_service import ThreatMapService
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.paths_engine import ThreatPathEngine
from app.services.investigation.findings import FindingsEngine


class DFIRReportService:
    """
    Comprehensive Digital Forensics & Incident Response (DFIR) Report Synthesizer.
    Correlates evidence, maps ATT&CK techniques, constructs actionable remediation plans,
    and deduplicates threat artifacts.
    """

    def __init__(self, db: Session):
        self.db = db

    def generate_dfir_report(self, target_id: str) -> DFIRReportDTO:
        """
        Generate a complete DFIR executive report for either an investigation_id or analysis_id.
        """
        # 1. Lookup Investigation and/or EmailAnalysis Record
        inv_record = self.db.execute(
            select(InvestigationModel).where(
                (InvestigationModel.investigation_id == target_id)
                | (InvestigationModel.analysis_id == target_id)
            )
        ).scalars().first()

        target_analysis_id = inv_record.analysis_id if inv_record else target_id
        effective_inv_id = inv_record.investigation_id if inv_record else f"INV-{target_id}"

        # 2. Eagerly load authoritative EmailAnalysis record
        analysis = self.db.execute(
            select(EmailAnalysisModel)
            .options(
                joinedload(EmailAnalysisModel.metadata_record),
                joinedload(EmailAnalysisModel.authentication),
                selectinload(EmailAnalysisModel.urls),
                selectinload(EmailAnalysisModel.ips),
                selectinload(EmailAnalysisModel.attachments),
                selectinload(EmailAnalysisModel.relay_hops),
            )
            .where(EmailAnalysisModel.analysis_id == target_analysis_id)
        ).scalars().first()

        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "ANALYSIS_NOT_FOUND", "message": f"No analysis or investigation record found for '{target_id}'."},
            )

        # 3. Dynamic threat map & routing telemetry
        threat_map_service = ThreatMapService(self.db)
        try:
            threat_map = threat_map_service.get_investigation_threat_map(target_id)
            threat_map_dict = threat_map.model_dump()
        except Exception:
            threat_map_dict = None

        # 4. Extract entities, relationships, paths, and findings
        entity_builder = EntityBuilder(analysis, effective_inv_id)
        entities = entity_builder.build_all_entities()
        
        rel_builder = RelationshipBuilder(analysis, effective_inv_id, entities)
        relationships = rel_builder.build_all_relationships()
        
        findings_engine = FindingsEngine(analysis, effective_inv_id, entities, relationships)
        findings_dicts = findings_engine.generate_findings()

        paths_engine = ThreatPathEngine(analysis, effective_inv_id, entities, relationships)
        threat_paths_dicts = paths_engine.compute_threat_paths()

        # 5. Map MITRE ATT&CK Matrix Techniques
        mitre_matrix = self._map_mitre_techniques(analysis, findings_dicts, threat_map_dict)

        # 6. Synthesize Prioritized Remediation Plan
        remediation_plan = self._generate_remediation_plan(analysis, findings_dicts, threat_map_dict)

        # 7. Deduplicate and Categorize IoCs
        iocs = self._extract_iocs(analysis)

        # 8. Construct Executive Narrative & Verdict
        executive_summary = self._synthesize_executive_summary(analysis, findings_dicts, threat_paths_dicts, threat_map_dict)

        # 9. Format Metadata & Forensic Timeline
        meta = analysis.metadata_record
        from_display = getattr(meta, "from_display_name", None) or getattr(meta, "from_name", None) if meta else None
        to_email_str = (
            meta.to_recipients[0]
            if (meta and getattr(meta, "to_recipients", None) and isinstance(meta.to_recipients, list))
            else (getattr(meta, "to_email", None) or "Unknown")
        )
        date_str = (
            meta.date_header
            if (meta and getattr(meta, "date_header", None))
            else (str(getattr(meta, "date", None)) if meta and getattr(meta, "date", None) else None)
        )
        email_metadata = {
            "from_email": meta.from_email if meta else "Unknown",
            "from_name": from_display,
            "to_email": to_email_str,
            "reply_to": meta.reply_to if meta else None,
            "subject": meta.subject if meta else "No Subject",
            "date": date_str,
            "message_id": meta.message_id if meta else None,
            "filename": analysis.filename,
            "sha256": analysis.sha256,
            "origin_ip": analysis.probable_origin_ip,
        }

        # Build evidentiary timeline
        timeline = self._build_forensic_timeline(analysis)

        report_id = f"RPT-{uuid.uuid4().hex[:10].upper()}"

        return DFIRReportDTO(
            report_id=report_id,
            investigation_id=effective_inv_id,
            analysis_id=analysis.analysis_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            generated_by="AEGIS Automated Forensic Intelligence Engine v2.0",
            case_reference=f"CAS-{analysis.analysis_id.replace('ANL-', '')}",
            email_metadata=email_metadata,
            executive_summary=executive_summary,
            mitre_matrix=mitre_matrix,
            remediation_plan=remediation_plan,
            iocs=iocs,
            evidentiary_findings=findings_dicts,
            forensic_timeline=timeline,
            threat_paths=threat_paths_dicts,
            transit_route_summary=threat_map_dict,
        )

    def _map_mitre_techniques(
        self,
        analysis: EmailAnalysisModel,
        findings: List[Dict[str, Any]],
        threat_map: Optional[Dict[str, Any]],
    ) -> List[MitreTechniqueDTO]:
        """Automatically match evidentiary signals to MITRE ATT&CK Enterprise Matrix."""
        techniques: List[MitreTechniqueDTO] = []
        seen_ids = set()

        meta = analysis.metadata_record
        threat_type = (analysis.threat_type or "").lower()
        risk_score = analysis.risk_score or 0

        # T1566.002 - Spearphishing Link
        urls = list(analysis.urls or [])
        url_strings = [
            (getattr(u, "normalized_url", None) or getattr(u, "original_url", None) or getattr(u, "url", ""))
            for u in urls
        ]
        malicious_urls = [
            (getattr(u, "normalized_url", None) or getattr(u, "original_url", None) or getattr(u, "url", ""))
            for u in urls
            if getattr(u, "is_suspicious", False) or getattr(u, "risk_score", 0) >= 60
        ]
        if urls or "phish" in threat_type or any("url" in f.get("reason_code", "").lower() for f in findings):
            matched = malicious_urls or [u for u in url_strings[:3] if u]
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1566.002",
                    name="Spearphishing Link",
                    tactic="Initial Access",
                    description="Adversary delivers targeted email containing deceptive hyperlinks pointing to malicious credential harvesting or delivery infrastructure.",
                    matched_indicators=matched or ["Extracted malicious hyperlinks from message body"],
                    confidence=0.95 if malicious_urls else 0.80,
                    url="https://attack.mitre.org/techniques/T1566/002/",
                )
            )
            seen_ids.add("T1566.002")

        # T1656 - Impersonation
        disp_name = getattr(meta, "from_display_name", None) or getattr(meta, "from_name", None) if meta else None
        if (
            "bec" in threat_type
            or "impersonat" in threat_type
            or (disp_name and any(k in disp_name.lower() for k in ["microsoft", "bank", "security", "officer", "executive", "ceo", "cfo", "admin", "authority", "support", "paypal", "apple", "google"]))
            or any("impersonat" in f.get("reason_code", "").lower() or "spoof" in f.get("reason_code", "").lower() for f in findings)
        ):
            disp = disp_name or "Executive Brand"
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1656",
                    name="Impersonation",
                    tactic="Defense Evasion",
                    description=f"Adversary impersonates trusted executive or corporate authority identity ('{disp}') to deceive the victim into unauthorized action.",
                    matched_indicators=[f"Sender Display: {disp}", f"From Header: {meta.from_email if meta else 'N/A'}"],
                    confidence=0.92,
                    url="https://attack.mitre.org/techniques/T1656/",
                )
            )
            seen_ids.add("T1656")

        # T1586.002 - Email Accounts (Reply-To Deception / BEC)
        if meta and meta.reply_to and meta.from_email:
            reply_domain = meta.reply_to.split("@")[-1].lower() if "@" in meta.reply_to else ""
            from_domain = meta.from_email.split("@")[-1].lower() if "@" in meta.from_email else ""
            if reply_domain and from_domain and reply_domain != from_domain:
                techniques.append(
                    MitreTechniqueDTO(
                        technique_id="T1586.002",
                        name="Email Accounts",
                        tactic="Resource Development",
                        description=f"Adversary utilizes an anomalous Reply-To mailbox ({meta.reply_to}) diverging from the sender domain ({from_domain}) to redirect response communications.",
                        matched_indicators=[f"From: {meta.from_email}", f"Reply-To: {meta.reply_to}"],
                        confidence=0.88,
                        url="https://attack.mitre.org/techniques/T1586/002/",
                    )
                )
                seen_ids.add("T1586.002")

        # T1056.003 - App Credential Prompt (Credential Harvesting)
        has_login_url = any(any(k in u.lower() for k in ["login", "verify", "auth", "account", "secure", "update"]) for u in url_strings)
        if (
            "phish" in threat_type
            or has_login_url
            or any("login" in f.get("description", "").lower() or "credential" in f.get("description", "").lower() for f in findings)
        ):
            cand_urls = [u for u in url_strings if any(k in u.lower() for k in ["login", "verify", "auth", "account", "secure", "update"])]
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1056.003",
                    name="App Credential Prompt",
                    tactic="Credential Access",
                    description="Adversary mimics authentic service authentication interfaces to harvest user passwords and session tokens.",
                    matched_indicators=cand_urls or [u for u in url_strings[:2] if u] or ["Simulated authentication portals"],
                    confidence=0.90,
                    url="https://attack.mitre.org/techniques/T1056/003/",
                )
            )
            seen_ids.add("T1056.003")

        # T1090.003 - Multi-hop Proxy: Tor
        hops = threat_map.get("hops", []) if threat_map else []
        tor_hops = [h for h in hops if h.get("location", {}).get("is_tor") or "tor" in (h.get("location", {}).get("as_org", "").lower())]
        if tor_hops or any("tor" in a.lower() for a in (threat_map.get("anomalies", []) if threat_map else [])):
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1090.003",
                    name="Multi-hop Proxy: Tor",
                    tactic="Command and Control",
                    description="Adversary routes mail traffic through the Tor anonymity network to obscure the originating autonomous system and physical jurisdiction.",
                    matched_indicators=[f"Tor Exit Node IP: {h.get('ip')}" for h in tor_hops] or ["Tor transit anomaly detected"],
                    confidence=0.98,
                    url="https://attack.mitre.org/techniques/T1090/003/",
                )
            )
            seen_ids.add("T1090.003")

        # T1566.001 - Spearphishing Attachment
        attachments = list(analysis.attachments or [])
        if attachments:
            att_names = [a.filename for a in attachments if getattr(a, "filename", None)]
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1566.001",
                    name="Spearphishing Attachment",
                    tactic="Initial Access",
                    description="Adversary delivers malicious file payload via email attachment to achieve code execution or payload staging on endpoint.",
                    matched_indicators=att_names or ["Email attachment payload"],
                    confidence=0.85,
                    url="https://attack.mitre.org/techniques/T1566/001/",
                )
            )
            seen_ids.add("T1566.001")

        # T1583.001 - Domains (Lookalike / Typo-squatting)
        if any("lookalike" in f.get("reason_code", "").lower() or "typo" in f.get("reason_code", "").lower() for f in findings):
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1583.001",
                    name="Domains",
                    tactic="Resource Development",
                    description="Adversary acquired homoglyph or lookalike domains mimicking legitimate brand infrastructure.",
                    matched_indicators=[f.get("title", "Lookalike domain") for f in findings if "lookalike" in f.get("reason_code", "").lower()],
                    confidence=0.91,
                    url="https://attack.mitre.org/techniques/T1583/001/",
                )
            )
            seen_ids.add("T1583.001")

        # Default fallback if high risk but no specific technique matched
        if not techniques and risk_score >= 60:
            techniques.append(
                MitreTechniqueDTO(
                    technique_id="T1566",
                    name="Phishing",
                    tactic="Initial Access",
                    description="Adversary sent social engineering email communication to induce target actions.",
                    matched_indicators=[f"Risk Score: {risk_score}/100", f"Classification: {threat_type.upper()}"],
                    confidence=0.75,
                    url="https://attack.mitre.org/techniques/T1566/",
                )
            )

        return techniques

    def _generate_remediation_plan(
        self,
        analysis: EmailAnalysisModel,
        findings: List[Dict[str, Any]],
        threat_map: Optional[Dict[str, Any]],
    ) -> List[RemediationActionDTO]:
        """Generate prioritized SOC remediation checklist (P0, P1, P2)."""
        actions: List[RemediationActionDTO] = []
        meta = analysis.metadata_record
        urls = list(analysis.urls or [])
        threat_type = (analysis.threat_type or "").lower()

        # P0 Immediate Containment Actions
        actions.append(
            RemediationActionDTO(
                action_id="ACT-01",
                priority="P0",
                category="Containment",
                title="Perimeter DNS & URL Gateway Blacklisting",
                description="Immediately block all extracted domains and URL endpoints across Secure Web Gateways (SWG), Next-Gen Firewalls, and DNS resolvers.",
                target_system="DNS / Secure Web Gateway",
                automated_action="POST /api/v1/integrations/firewall/block-indicators",
            )
        )

        if analysis.probable_origin_ip or (threat_map and threat_map.get("hops")):
            origin_ip = analysis.probable_origin_ip or threat_map["hops"][0].get("ip", "N/A")
            actions.append(
                RemediationActionDTO(
                    action_id="ACT-02",
                    priority="P0",
                    category="Containment",
                    title="Inbound MTA IP Block & Session Termination",
                    description=f"Add sender origin IP ({origin_ip}) to inbound mail transport reject lists and drop existing active TCP/TLS sessions.",
                    target_system="Email Gateway / MTA",
                    automated_action="POST /api/v1/integrations/mta/ip-blacklist",
                )
            )

        if "phish" in threat_type or "credential" in threat_type:
            target_user = (
                meta.to_recipients[0]
                if (meta and getattr(meta, "to_recipients", None) and isinstance(meta.to_recipients, list) and len(meta.to_recipients) > 0)
                else (getattr(meta, "to_email", None) or "Target Recipient")
            )
            actions.append(
                RemediationActionDTO(
                    action_id="ACT-03",
                    priority="P0",
                    category="Containment",
                    title="Recipient Credential Invalidation & MFA Re-enrollment",
                    description=f"Revoke active OAuth refresh tokens and force immediate password reset for targeted account ({target_user}) to mitigate token theft.",
                    target_system="Identity Provider (Azure AD / Okta)",
                    automated_action="POST /api/v1/integrations/idp/revoke-tokens",
                )
            )

        # P1 Eradication Actions
        actions.append(
            RemediationActionDTO(
                action_id="ACT-04",
                priority="P1",
                category="Eradication",
                title="Tenant-Wide Mailbox Sweep & Hard Delete",
                description=f"Execute an automated compliance search across all organization mailboxes using Message-ID and Subject '{meta.subject if meta else 'Threat'}' to hard delete replica messages.",
                target_system="Email Gateway / Exchange Online",
                automated_action="POST /api/v1/integrations/exchange/purge-message",
            )
        )

        actions.append(
            RemediationActionDTO(
                action_id="ACT-05",
                priority="P1",
                category="Eradication",
                title="EDR Retroactive Fleet IoC Hunt",
                description="Broadcast extracted SHA256 hashes, hostnames, and IP indicators to CrowdStrike / Microsoft Defender to identify any secondary host compromise.",
                target_system="Endpoint EDR (CrowdStrike / Defender)",
                automated_action="POST /api/v1/integrations/edr/sweep",
            )
        )

        # P2 Hardening Actions
        actions.append(
            RemediationActionDTO(
                action_id="ACT-06",
                priority="P2",
                category="Hardening",
                title="DMARC Policy Hardening to 'p=reject'",
                description="Audit domain SPF records and ensure organizational DMARC records are configured to strict quarantine or reject policy to prevent outbound spoofing.",
                target_system="DNS Zone Authority",
                automated_action=None,
            )
        )

        actions.append(
            RemediationActionDTO(
                action_id="ACT-07",
                priority="P2",
                category="User Communication",
                title="Targeted Security Awareness Notification",
                description=f"Dispatch an informative threat alert to the targeted department detailing the '{analysis.threat_type or 'Phishing'}' vector and evasion tactics observed.",
                target_system="SOC Security Awareness Portal",
                automated_action=None,
            )
        )

        return actions

    def _extract_iocs(self, analysis: EmailAnalysisModel) -> List[IoCItemDTO]:
        """Compile and deduplicate threat indicators of compromise."""
        iocs: List[IoCItemDTO] = []
        seen = set()

        meta = analysis.metadata_record
        sev = analysis.severity or "high"

        # 1. URLs
        for url_record in analysis.urls or []:
            u = getattr(url_record, "normalized_url", None) or getattr(url_record, "original_url", None) or getattr(url_record, "url", "")
            if u and u not in seen:
                seen.add(u)
                iocs.append(
                    IoCItemDTO(
                        ioc_type="URL",
                        value=u,
                        threat_context="Extracted hyperlink in email body/html",
                        severity="critical" if getattr(url_record, "is_suspicious", False) else "high",
                        killchain_stage="Initial Access",
                    )
                )

        # 2. Public IPs
        for ip_record in analysis.ips or []:
            ip_val = ip_record.ip
            if ip_val and ip_val not in seen and not getattr(ip_record, "is_private", False):
                seen.add(ip_val)
                iocs.append(
                    IoCItemDTO(
                        ioc_type="IP",
                        value=ip_val,
                        threat_context=f"Infrastructure IP ({getattr(ip_record, 'city', 'Unknown')}, {getattr(ip_record, 'country_name', 'N/A')})",
                        severity="high",
                        killchain_stage="Command & Control",
                    )
                )

        # 3. Probable Origin IP
        if analysis.probable_origin_ip and analysis.probable_origin_ip not in seen:
            seen.add(analysis.probable_origin_ip)
            iocs.append(
                IoCItemDTO(
                    ioc_type="IP",
                    value=analysis.probable_origin_ip,
                    threat_context="First external SMTP transmission relay",
                    severity="critical",
                    killchain_stage="Initial Access",
                )
            )

        # 4. Sender & Reply-To Addresses
        if meta and meta.from_email and meta.from_email not in seen:
            seen.add(meta.from_email)
            iocs.append(
                IoCItemDTO(
                    ioc_type="EmailAddress",
                    value=meta.from_email,
                    threat_context="Sender envelope mailbox",
                    severity="medium",
                    killchain_stage="Initial Access",
                )
            )

        if meta and meta.reply_to and meta.reply_to not in seen and meta.reply_to != meta.from_email:
            seen.add(meta.reply_to)
            iocs.append(
                IoCItemDTO(
                    ioc_type="EmailAddress",
                    value=meta.reply_to,
                    threat_context="Deceptive Reply-To diversion address",
                    severity="high",
                    killchain_stage="Initial Access",
                )
            )

        # 5. File Hashes
        if analysis.sha256 and analysis.sha256 not in seen:
            seen.add(analysis.sha256)
            iocs.append(
                IoCItemDTO(
                    ioc_type="SHA256",
                    value=analysis.sha256,
                    threat_context="Cryptographic forensic seal of raw email file",
                    severity="info",
                    killchain_stage="Execution",
                )
            )

        return iocs

    def _synthesize_executive_summary(
        self,
        analysis: EmailAnalysisModel,
        findings: List[Dict[str, Any]],
        threat_paths: List[Dict[str, Any]],
        threat_map: Optional[Dict[str, Any]],
    ) -> ExecutiveSummaryDTO:
        """Synthesize high-level executive assessment and risk narrative."""
        score = analysis.risk_score or 0
        sev = (analysis.severity or "medium").upper()
        threat_type = (analysis.threat_type or "suspicious").replace("_", " ").title()
        meta = analysis.metadata_record
        confidence = analysis.ai_confidence or 0.88

        if score >= 80:
            verdict = "MALICIOUS"
            impact = "High potential for unauthorized credential harvesting, identity compromise, or financial fraud."
        elif score >= 50:
            verdict = "SUSPICIOUS"
            impact = "Moderate risk of social engineering engagement or policy violation."
        else:
            verdict = "BENIGN"
            impact = "Low operational impact; indicators consistent with legitimate corporate communication."

        from_display = getattr(meta, "from_display_name", None) or getattr(meta, "from_name", None) if meta else None
        from_str = f"'{from_display}' <{meta.from_email}>" if (meta and from_display) else (meta.from_email if meta else "an external sender")
        subject_str = f"'{meta.subject}'" if (meta and meta.subject) else "an unscheduled communication"

        anom_count = len(threat_map.get("anomalies", [])) if threat_map else 0
        hop_count = len(threat_map.get("hops", [])) if threat_map else 0

        from app.services.ai.summary_generator import generate_canonical_soc_summary
        narrative = generate_canonical_soc_summary(analysis)

        key_takeaways = [
            f"Threat Classification: {threat_type} ({verdict}) with {confidence * 100:.1f}% confidence.",
            f"Identified {len(findings)} technical findings including header authentication, URL reputation, and routing signals.",
            f"Extracted and deduplicated indicators across domains, public IP infrastructure, and sender envelopes.",
            f"Prioritized containment playbook established with immediate P0 actions for gateway and identity enforcement.",
        ]

        attack_vector = f"Social Engineering ({threat_type}) via Inbound SMTP Delivery"

        return ExecutiveSummaryDTO(
            verdict=verdict,
            classification=threat_type,
            risk_score=score,
            severity=sev,
            ai_confidence=confidence,
            narrative=narrative,
            key_takeaways=key_takeaways,
            attack_vector=attack_vector,
            potential_impact=impact,
        )

    def _build_forensic_timeline(self, analysis: EmailAnalysisModel) -> List[Dict[str, Any]]:
        """Construct evidentiary chronological timeline."""
        events: List[Dict[str, Any]] = []
        meta = analysis.metadata_record

        # 1. Received header hops
        for hop in analysis.relay_hops or []:
            events.append({
                "timestamp": str(hop.timestamp) if hop.timestamp else "N/A",
                "title": f"Relay Hop #{hop.hop_number}: {hop.ip or 'MTA'}",
                "event_type": "relay_transmission",
                "description": f"Transferred from '{hop.from_server or 'Unknown'}' to '{hop.by_server or 'Gateway'}' via {hop.protocol or 'SMTP'}.",
                "source": "RFC 5322 Received Headers",
            })

        # 2. Email Date
        date_str = getattr(meta, "date_header", None) or getattr(meta, "date", None) if meta else None
        if date_str:
            events.append({
                "timestamp": str(date_str),
                "title": "Email Message Date Header",
                "event_type": "message_origination",
                "description": f"Message submitted by client with Subject '{meta.subject or 'N/A'}'.",
                "source": "Date Header",
            })

        # 3. Analysis Completion
        if analysis.completed_at:
            events.append({
                "timestamp": str(analysis.completed_at),
                "title": "AEGIS Automated Forensic Ingestion",
                "event_type": "analysis_completed",
                "description": f"Static ML extraction, graph synthesis, and risk assessment completed (Score: {analysis.risk_score}/100).",
                "source": "AEGIS Engine",
            })

        return events

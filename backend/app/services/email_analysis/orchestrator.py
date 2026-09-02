import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.storage.base import EvidenceStorage
from app.storage.local import LocalEvidenceStorage
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
    AnalysisReasonModel,
)
from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    EmailMetadataSchema,
    ClassificationResultSchema,
    AuthenticationResultsSchema,
    RelayHopSchema,
    ExtractedUrlSchema,
    ExtractedIpSchema,
    AttachmentMetadataSchema,
    ThreatIndicatorSchema,
    AnalysisReasonSchema,
    ProbableOriginSchema,
    EvidenceMetadataSchema,
    ModelInfoSchema,
    TimingMetricsSchema,
    AuthStatusItem,
)
from app.services.email_analysis.parser import EmailParser, ParsedEmailData
from app.services.email_analysis.headers import HeaderAnalyzer
from app.services.email_analysis.urls import UrlExtractor
from app.services.email_analysis.domains import DomainAnalyzer
from app.services.email_analysis.ips import IpExtractor
from app.services.email_analysis.attachments import AttachmentAnalyzer
from app.services.email_analysis.body import BodyAnalyzer
from app.services.email_analysis.features import FeatureExtractor
from app.services.email_analysis.classifier import SklearnThreatClassifier
from app.services.email_analysis.risk_scoring import RiskScoringEngine
from app.services.email_analysis.explanation import ExplanationEngine
from app.services.ml.confidence_calculator import calculate_confidence


class AnalysisOrchestrator:
    """Unified DFIR email analysis orchestration pipeline (Single Pipeline for Sync & Async Worker)."""

    def __init__(self, db: Session, storage: Optional[EvidenceStorage] = None):
        self.db = db
        self.storage = storage or LocalEvidenceStorage()
        self.classifier = SklearnThreatClassifier()

    def process_email(
        self,
        raw_bytes: bytes,
        filename: str = "untrusted_input.eml",
        analysis_id: Optional[str] = None,
        force_reanalysis: bool = False,
    ) -> EmailAnalysisResponse:
        start_time = time.time()
        start_dt = datetime.now(timezone.utc)

        # 1. Validate size
        if len(raw_bytes) > settings.max_email_size_bytes:
            raise ValueError(f"Email size ({len(raw_bytes)} bytes) exceeds configured limit ({settings.MAX_EMAIL_SIZE_MB} MB)")

        if not raw_bytes or len(raw_bytes.strip()) == 0:
            raise ValueError("Uploaded email content is empty or unreadable.")

        # 2. Compute SHA-256 integrity seal
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # 3. Idempotency check
        if not force_reanalysis:
            existing = self.db.execute(
                select(EmailAnalysisModel).where(
                    EmailAnalysisModel.sha256 == sha256,
                    EmailAnalysisModel.status == "completed"
                ).order_by(EmailAnalysisModel.created_at.desc())
            ).scalars().first()

            if existing:
                logger.info(
                    f"Idempotency match: Returning existing analysis record for SHA-256 {sha256[:16]}...",
                    extra={"analysis_id": existing.analysis_id, "status": "completed"}
                )
                return self.build_response_dto(existing)

        # Generate unique analysis ID if not provided
        if not analysis_id:
            ts_str = datetime.now().strftime("%Y%m%d%H%M%S")
            analysis_id = f"ANL-{ts_str}-{sha256[:6].upper()}"

        logger.info(
            f"Initiating DFIR analysis pipeline for {analysis_id}",
            extra={"analysis_id": analysis_id, "stage": "validating", "sha256": sha256}
        )

        # 4. Store original evidence
        storage_ref = self.storage.save_evidence(analysis_id, raw_bytes, filename)

        # 5. Initialize / Update Database Record
        analysis_record = self.db.execute(
            select(EmailAnalysisModel).where(EmailAnalysisModel.analysis_id == analysis_id)
        ).scalars().first()

        if not analysis_record:
            analysis_record = EmailAnalysisModel(
                analysis_id=analysis_id,
                filename=filename,
                sha256=sha256,
                file_size_bytes=len(raw_bytes),
                status="processing",
                stage="parsing",
                progress=15,
                queued_at=start_dt,
                started_at=start_dt,
            )
            self.db.add(analysis_record)
            self.db.commit()
            self.db.refresh(analysis_record)

        try:
            # Stage: Parsing (25%)
            analysis_record.stage = "parsing"
            analysis_record.progress = 25
            self.db.commit()
            parsed_data: ParsedEmailData = EmailParser.parse_bytes(raw_bytes, filename=filename)

            # Stage: Analyzing Headers & Relay Chain (40%)
            analysis_record.stage = "analyzing_headers"
            analysis_record.progress = 40
            self.db.commit()
            relay_hops = HeaderAnalyzer.analyze_relay_hops(parsed_data.headers)
            auth_results = HeaderAnalyzer.analyze_authentication(parsed_data.headers)

            # Stage: Extracting Indicators (55%)
            analysis_record.stage = "extracting_indicators"
            analysis_record.progress = 55
            self.db.commit()

            # URLs
            extracted_urls = UrlExtractor.extract_urls(
                parsed_data.body_plain,
                parsed_data.body_html,
                parsed_data.headers
            )

            # Domains & Lookalikes
            domain_lookalikes: List[str] = []
            suspicious_tld_count = 0

            # Check Sender From Domain
            from_dom = parsed_data.metadata.get("from_domain")
            if from_dom:
                is_from_spoof, from_spoof_desc = DomainAnalyzer.check_lookalike(from_dom)
                if is_from_spoof and from_spoof_desc:
                    domain_lookalikes.append(f"Sender {from_spoof_desc}")
                if DomainAnalyzer.is_suspicious_tld(from_dom):
                    suspicious_tld_count += 1

            for u in extracted_urls:
                if u.domain:
                    is_spoof, spoof_desc = DomainAnalyzer.check_lookalike(u.domain)
                    if is_spoof and spoof_desc:
                        domain_lookalikes.append(spoof_desc)
                    if DomainAnalyzer.is_suspicious_tld(u.domain):
                        suspicious_tld_count += 1

            # Sender Inconsistencies
            sender_anomalies = DomainAnalyzer.analyze_sender_domains(
                parsed_data.metadata.get("from_email"),
                parsed_data.metadata.get("reply_to"),
                parsed_data.metadata.get("return_path"),
            )

            # IPs & Probable Origin Candidate
            extracted_ips, probable_origin = IpExtractor.extract_ips(
                relay_hops,
                parsed_data.headers,
                extracted_urls
            )

            # Attachments
            attachments_meta, att_assessment = AttachmentAnalyzer.analyze_attachments(
                parsed_data.attachments_raw
            )

            # Body Safe Extraction & Linguistics
            clean_body_text, body_preview = BodyAnalyzer.extract_safe_text(
                parsed_data.body_plain,
                parsed_data.body_html
            )
            linguistics = BodyAnalyzer.analyze_linguistics(
                clean_body_text,
                parsed_data.metadata.get("subject")
            )

            # Stage: Feature Extraction & ML Classification (70%)
            analysis_record.stage = "running_ml"
            analysis_record.progress = 70
            self.db.commit()

            features = FeatureExtractor.extract_features(
                parsed_data.metadata,
                auth_results,
                relay_hops,
                extracted_urls,
                extracted_ips,
                attachments_meta,
                linguistics,
                sender_anomalies,
                domain_lookalikes,
                suspicious_tld_count,
            )
            feature_hash = FeatureExtractor.compute_feature_hash(features)

            logger.info(
                f"Analysis {analysis_id} Feature Vector: url_count={features.get('url_count', 0)}, "
                f"urgency={features.get('urgency_score', 0)}, credential={features.get('credential_request_score', 0)}, "
                f"financial={features.get('financial_request_score', 0)}, impersonation={features.get('impersonation_score', 0)}, "
                f"lookalikes={features.get('lookalike_domain_count', 0)}, attachments={features.get('attachment_count', 0)}, "
                f"feature_hash={feature_hash[:12]}..."
            )

            predicted_type, ai_confidence, feature_contributions, ml_available = self.classifier.predict(features)

            # Recalibrate detection confidence based on multi-vector evidentiary signals
            signals_list = []
            if features.get("lookalike_domain_count", 0) > 0:
                signals_list.append("lookalike_domain")
            if features.get("credential_request_score", 0) > 0.2:
                signals_list.append("credential_request")
            if features.get("financial_request_score", 0) > 0.2:
                signals_list.append("financial_request")
            if features.get("urgency_score", 0) > 0.2:
                signals_list.append("urgency_language")
            if features.get("executable_attachment_signal", 0) > 0:
                signals_list.append("executable_attachment")
            if features.get("suspicious_attachment_count", 0) > 0:
                signals_list.append("suspicious_attachment")
            if features.get("reply_to_mismatch", 0) > 0:
                signals_list.append("reply_to_mismatch")

            auth_dict = {
                "spf_pass": auth_results.spf.status == "pass",
                "spf_result": auth_results.spf.status,
                "dkim_pass": auth_results.dkim.status == "pass",
                "dkim_result": auth_results.dkim.status,
                "dmarc_pass": auth_results.dmarc.status == "pass",
                "dmarc_result": auth_results.dmarc.status,
            }
            route_anomalies = [h.anomaly_reason for h in relay_hops if getattr(h, "is_anomaly", False) and getattr(h, "anomaly_reason", None)]
            calibrated_conf = calculate_confidence(signals_list, auth_dict, route_anomalies, base_confidence=ai_confidence or 0.70)
            if predicted_type != "benign":
                ai_confidence = max(ai_confidence or 0.70, calibrated_conf)

            # Stage: Risk Calculation (85%)
            analysis_record.stage = "calculating_risk"
            analysis_record.progress = 85
            self.db.commit()

            risk_score, severity, score_components = RiskScoringEngine.calculate_risk(
                predicted_type,
                ai_confidence,
                features,
                ml_available=ml_available,
            )

            # Stage: Explanation Generation (92%)
            analysis_record.stage = "generating_explanation"
            analysis_record.progress = 92
            self.db.commit()

            reasons = ExplanationEngine.generate_reasons(
                auth_results,
                extracted_urls,
                attachments_meta,
                sender_anomalies,
                domain_lookalikes,
                linguistics,
                features,
            )

            # Stage: Database Persistence & Finalization (100%)
            analysis_record.stage = "saving_results"
            analysis_record.progress = 98
            
            # Update Parent Record
            end_dt = datetime.now(timezone.utc)
            duration_ms = int((time.time() - start_time) * 1000)

            analysis_record.threat_type = predicted_type
            analysis_record.risk_score = risk_score
            analysis_record.severity = severity
            analysis_record.ai_confidence = ai_confidence
            analysis_record.attachment_assessment = att_assessment
            analysis_record.feature_hash = feature_hash
            analysis_record.score_components = score_components
            analysis_record.model_name = "aegis_email_classifier"
            analysis_record.model_version = "1.0.0"
            analysis_record.feature_schema_version = FeatureExtractor.FEATURE_SCHEMA_VERSION
            analysis_record.analysis_engine_version = FeatureExtractor.RULE_ENGINE_VERSION
            analysis_record.probable_origin_ip = probable_origin.ip if probable_origin else None
            analysis_record.probable_origin_confidence = probable_origin.confidence if probable_origin else None
            analysis_record.probable_origin_source = probable_origin.source if probable_origin else None
            analysis_record.completed_at = end_dt
            analysis_record.processing_duration_ms = duration_ms
            analysis_record.status = "completed"
            analysis_record.stage = "completed"
            analysis_record.progress = 100

            # Clean previous child rows if re-analyzing
            self._cleanup_analysis_children(analysis_id)

            # 1. Metadata Record
            meta_rec = EmailMetadataModel(
                analysis_id=analysis_id,
                from_header=parsed_data.metadata.get("from"),
                from_display_name=parsed_data.metadata.get("from_display_name"),
                from_email=parsed_data.metadata.get("from_email"),
                from_domain=parsed_data.metadata.get("from_domain"),
                to_recipients=parsed_data.metadata.get("to", []),
                cc_recipients=parsed_data.metadata.get("cc", []),
                bcc_recipients=parsed_data.metadata.get("bcc", []),
                reply_to=parsed_data.metadata.get("reply_to"),
                return_path=parsed_data.metadata.get("return_path"),
                subject=parsed_data.metadata.get("subject"),
                date_header=parsed_data.metadata.get("date"),
                message_id=parsed_data.metadata.get("message_id"),
                body_plain=parsed_data.body_plain,
                body_html_stripped=clean_body_text,
            )
            self.db.add(meta_rec)

            # 2. Raw Headers
            for h_name, h_val in parsed_data.headers:
                self.db.add(EmailHeaderModel(
                    analysis_id=analysis_id,
                    header_name=h_name,
                    header_value=h_val
                ))

            # 3. Relay Hops
            for hop in relay_hops:
                self.db.add(EmailRelayHopModel(
                    analysis_id=analysis_id,
                    hop_number=hop.hop_number,
                    from_server=hop.from_server,
                    by_server=hop.by_server,
                    ip=hop.ip,
                    is_private_ip=hop.is_private_ip,
                    timestamp=hop.timestamp,
                    protocol=hop.protocol,
                    delay_seconds=hop.delay_seconds,
                    is_origin_node=hop.is_origin_node,
                    is_anomaly=hop.is_anomaly,
                    anomaly_reason=hop.anomaly_reason,
                    raw_header=hop.raw_header,
                ))

            # 4. Authentication Record
            self.db.add(EmailAuthenticationModel(
                analysis_id=analysis_id,
                spf_status=auth_results.spf.status,
                spf_details=auth_results.spf.details,
                dkim_status=auth_results.dkim.status,
                dkim_details=auth_results.dkim.details,
                dmarc_status=auth_results.dmarc.status,
                dmarc_details=auth_results.dmarc.details,
            ))

            # 5. URLs
            for u in extracted_urls:
                self.db.add(EmailUrlModel(
                    analysis_id=analysis_id,
                    original_url=u.original_url,
                    normalized_url=u.normalized_url,
                    scheme=u.scheme,
                    hostname=u.hostname,
                    domain=u.domain,
                    path=u.path,
                    query=u.query,
                    is_ip_based=u.is_ip_based,
                    is_shortened=u.is_shortened,
                    is_lookalike=u.is_lookalike,
                    is_punycode=u.is_punycode,
                    has_redirect=u.has_redirect,
                    risk_score=u.risk_score,
                    threat_level=u.threat_level,
                    reason=u.reason,
                    source_location=u.source_location,
                ))

            # 6. IPs
            for ip_item in extracted_ips:
                self.db.add(EmailIpModel(
                    analysis_id=analysis_id,
                    ip=ip_item.ip,
                    ip_version=ip_item.ip_version,
                    is_private=ip_item.is_private,
                    source=ip_item.source,
                    source_location=ip_item.source_location,
                    confidence=ip_item.confidence,
                    is_probable_origin=ip_item.is_probable_origin,
                ))

            # 7. Attachments
            for att in attachments_meta:
                self.db.add(EmailAttachmentModel(
                    analysis_id=analysis_id,
                    filename=att.filename,
                    content_type=att.content_type,
                    content_disposition=att.content_disposition,
                    size_bytes=att.size_bytes,
                    sha256=att.sha256,
                    is_double_extension=att.is_double_extension,
                    is_executable=att.is_executable,
                    is_suspicious=att.is_suspicious,
                    detected_signals=att.detected_signals,
                ))

            # 8. Normalized Indicators (for future Neo4j & Threat Map ingest)
            # Email sender indicator
            if parsed_data.metadata.get("from_email"):
                self.db.add(EmailIndicatorModel(
                    analysis_id=analysis_id,
                    indicator_type="email",
                    value=parsed_data.metadata["from_email"],
                    normalized_value=parsed_data.metadata["from_email"].lower(),
                    source="from_header",
                    source_location="From",
                    confidence=0.95,
                    severity=severity,
                ))

            # Reply-to indicator
            if parsed_data.metadata.get("reply_to"):
                self.db.add(EmailIndicatorModel(
                    analysis_id=analysis_id,
                    indicator_type="email",
                    value=parsed_data.metadata["reply_to"],
                    normalized_value=parsed_data.metadata["reply_to"].lower(),
                    source="reply_to_header",
                    source_location="Reply-To",
                    confidence=0.95,
                    severity="high" if any(a["code"] == "REPLY_TO_MISMATCH" for a in sender_anomalies) else "medium",
                ))

            # Domain indicators
            for u in extracted_urls:
                if u.domain:
                    self.db.add(EmailIndicatorModel(
                        analysis_id=analysis_id,
                        indicator_type="domain",
                        value=u.domain,
                        normalized_value=u.domain.lower(),
                        source="embedded_url",
                        source_location="Email Body",
                        confidence=0.85,
                        severity="critical" if u.is_lookalike else "medium",
                    ))

            # IP indicators
            for ip_item in extracted_ips:
                self.db.add(EmailIndicatorModel(
                    analysis_id=analysis_id,
                    indicator_type="ip",
                    value=ip_item.ip,
                    normalized_value=ip_item.ip,
                    source=ip_item.source,
                    source_location=ip_item.source_location,
                    confidence=ip_item.confidence,
                    severity="high" if ip_item.is_probable_origin else "medium",
                ))

            # Attachment hash indicators
            for att in attachments_meta:
                self.db.add(EmailIndicatorModel(
                    analysis_id=analysis_id,
                    indicator_type="attachment_hash",
                    value=att.sha256,
                    normalized_value=att.sha256.lower(),
                    source="attachment_payload",
                    source_location=att.filename,
                    confidence=1.0,
                    severity="critical" if att.is_suspicious else "medium",
                ))

            # 9. Reasons
            for r in reasons:
                self.db.add(AnalysisReasonModel(
                    analysis_id=analysis_id,
                    reason_code=r.reason_code,
                    severity=r.severity,
                    title=r.title,
                    description=r.description,
                    evidence_reference=r.evidence_reference,
                    weight=r.weight,
                ))

            self.db.commit()
            self.db.refresh(analysis_record)

            logger.info(
                f"DFIR pipeline completed: {predicted_type} (Risk: {risk_score}/100, AI: {int(ai_confidence*100)}%) in {duration_ms}ms",
                extra={"analysis_id": analysis_id, "status": "completed", "duration_ms": duration_ms}
            )

            return self.build_response_dto(analysis_record)

        except Exception as e:
            self.db.rollback()
            analysis_record.status = "failed"
            analysis_record.error_message = str(e)
            self.db.commit()
            logger.error(
                f"DFIR pipeline failed on {analysis_id}: {e}",
                extra={"analysis_id": analysis_id, "status": "failed"}
            )
            raise e

    def build_response_dto(self, record: EmailAnalysisModel) -> EmailAnalysisResponse:
        # Load related data if not loaded
        meta = record.metadata_record
        auth = record.authentication

        email_meta = EmailMetadataSchema(
            from_header=meta.from_header if meta else None,
            from_display_name=meta.from_display_name if meta else None,
            from_email=meta.from_email if meta else None,
            from_domain=meta.from_domain if meta else None,
            to=meta.to_recipients if meta and meta.to_recipients else [],
            cc=meta.cc_recipients if meta and meta.cc_recipients else [],
            bcc=meta.bcc_recipients if meta and meta.bcc_recipients else [],
            reply_to=meta.reply_to if meta else None,
            return_path=meta.return_path if meta else None,
            subject=meta.subject if meta else None,
            date=meta.date_header if meta else None,
            message_id=meta.message_id if meta else None,
            body_text_preview=meta.body_plain[:400] if meta and meta.body_plain else None,
        )

        classification = ClassificationResultSchema(
            threat_type=record.threat_type or "unknown",
            risk_score=record.risk_score or 0,
            severity=record.severity or "low",
            ai_confidence=record.ai_confidence,
            attachment_assessment=record.attachment_assessment or "clean",
            score_components=record.score_components or {},
        )

        authentication = AuthenticationResultsSchema(
            spf=AuthStatusItem(status=auth.spf_status if auth else "unknown", details=auth.spf_details if auth else None),
            dkim=AuthStatusItem(status=auth.dkim_status if auth else "unknown", details=auth.dkim_details if auth else None),
            dmarc=AuthStatusItem(status=auth.dmarc_status if auth else "unknown", details=auth.dmarc_details if auth else None),
        )

        relay_hops = [
            RelayHopSchema(
                hop_number=h.hop_number,
                from_server=h.from_server,
                by_server=h.by_server,
                ip=h.ip,
                is_private_ip=h.is_private_ip,
                timestamp=h.timestamp,
                protocol=h.protocol,
                delay_seconds=h.delay_seconds or 0,
                is_origin_node=h.is_origin_node,
                is_anomaly=h.is_anomaly,
                anomaly_reason=h.anomaly_reason,
                raw_header=h.raw_header,
            ) for h in (record.relay_hops or [])
        ]

        urls_list = [
            ExtractedUrlSchema(
                id=u.id,
                original_url=u.original_url,
                normalized_url=u.normalized_url,
                scheme=u.scheme,
                hostname=u.hostname,
                domain=u.domain,
                path=u.path,
                query=u.query,
                is_ip_based=u.is_ip_based,
                is_shortened=u.is_shortened,
                is_lookalike=u.is_lookalike,
                is_punycode=u.is_punycode,
                has_redirect=u.has_redirect,
                risk_score=u.risk_score,
                threat_level=u.threat_level,
                reason=u.reason,
                source_location=u.source_location,
            ) for u in (record.urls or [])
        ]

        ips_list = [
            ExtractedIpSchema(
                ip=i.ip,
                ip_version=i.ip_version,
                is_private=i.is_private,
                source=i.source,
                source_location=i.source_location,
                confidence=i.confidence,
                is_probable_origin=i.is_probable_origin,
            ) for i in (record.ips or [])
        ]

        attachments_list = [
            AttachmentMetadataSchema(
                filename=a.filename,
                content_type=a.content_type,
                content_disposition=a.content_disposition,
                size_bytes=a.size_bytes,
                sha256=a.sha256,
                is_double_extension=a.is_double_extension,
                is_executable=a.is_executable,
                is_suspicious=a.is_suspicious,
                detected_signals=a.detected_signals or [],
            ) for a in (record.attachments or [])
        ]

        reasons_list = [
            AnalysisReasonSchema(
                reason_code=r.reason_code,
                severity=r.severity,
                title=r.title,
                description=r.description,
                evidence_reference=r.evidence_reference,
                weight=r.weight,
            ) for r in (record.reasons or [])
        ]

        probable_origin = None
        if record.probable_origin_ip:
            probable_origin = ProbableOriginSchema(
                ip=record.probable_origin_ip,
                role="probable_origin_candidate",
                confidence=record.probable_origin_confidence or 0.8,
                source=record.probable_origin_source,
                basis=["received_header", "public_ip", "earliest_observed_hop"],
            )

        indicators_map = {
            "ips": ips_list,
            "domains": list(set(u.domain for u in urls_list if u.domain)),
            "urls": urls_list,
            "attachments": attachments_list,
            "all_indicators": [
                ThreatIndicatorSchema(
                    id=ind.id,
                    type=ind.indicator_type,
                    value=ind.value,
                    normalized_value=ind.normalized_value,
                    source=ind.source,
                    source_location=ind.source_location,
                    confidence=ind.confidence,
                    severity=ind.severity,
                    metadata=ind.indicator_metadata or {},
                ) for ind in (record.indicators or [])
            ]
        }

        return EmailAnalysisResponse(
            analysis_id=record.analysis_id,
            status=record.status,
            email=email_meta,
            classification=classification,
            authentication=authentication,
            relay_path=relay_hops,
            indicators=indicators_map,
            probable_origin=probable_origin,
            reasons=reasons_list,
            model=ModelInfoSchema(
                name=record.model_name or "aegis_email_classifier",
                version=record.model_version or "1.0.0",
                model_type="synthetic-data baseline",
                engine_version=record.analysis_engine_version or "1.0.0",
                feature_schema_version=record.feature_schema_version or "1.0",
                rule_engine_version=record.analysis_engine_version or "1.0",
                ml_available=self.classifier.ml_available if hasattr(self.classifier, "ml_available") else True,
                feature_hash=record.feature_hash,
            ),
            evidence=EvidenceMetadataSchema(
                sha256=record.sha256,
                filename=record.filename,
                file_size_bytes=record.file_size_bytes,
                integrity_status="Verified",
                storage_path=f"storage/emails/{record.analysis_id}/original.eml",
            ),
            timings=TimingMetricsSchema(
                queued_at=record.queued_at,
                started_at=record.started_at,
                completed_at=record.completed_at,
                processing_duration_ms=record.processing_duration_ms,
            ),
        )

    def _cleanup_analysis_children(self, analysis_id: str):
        """Remove child rows before re-persisting analysis."""
        from sqlalchemy import delete
        self.db.execute(delete(EmailMetadataModel).where(EmailMetadataModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailHeaderModel).where(EmailHeaderModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailRelayHopModel).where(EmailRelayHopModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailAuthenticationModel).where(EmailAuthenticationModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailUrlModel).where(EmailUrlModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailIpModel).where(EmailIpModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailAttachmentModel).where(EmailAttachmentModel.analysis_id == analysis_id))
        self.db.execute(delete(EmailIndicatorModel).where(EmailIndicatorModel.analysis_id == analysis_id))
        self.db.execute(delete(AnalysisReasonModel).where(AnalysisReasonModel.analysis_id == analysis_id))
        self.db.commit()

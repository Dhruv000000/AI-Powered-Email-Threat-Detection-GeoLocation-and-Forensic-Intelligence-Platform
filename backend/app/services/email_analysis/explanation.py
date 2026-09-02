from typing import List, Dict, Any
from app.schemas.email_analysis import (
    AnalysisReasonSchema,
    AuthenticationResultsSchema,
    ExtractedUrlSchema,
    AttachmentMetadataSchema,
)

class ExplanationEngine:
    """Forensic explanation engine mapping extracted evidence and features to structured reason codes."""

    @classmethod
    def generate_reasons(
        cls,
        auth: AuthenticationResultsSchema,
        urls: List[ExtractedUrlSchema],
        attachments: List[AttachmentMetadataSchema],
        sender_anomalies: List[Dict[str, Any]],
        domain_lookalikes: List[str],
        linguistics: Dict[str, Any],
        features: Dict[str, float],
    ) -> List[AnalysisReasonSchema]:
        reasons: List[AnalysisReasonSchema] = []

        # 1. Sender Mismatch Reasons
        for anom in sender_anomalies:
            reasons.append(
                AnalysisReasonSchema(
                    reason_code=anom.get("code", "SENDER_ANOMALY"),
                    severity=anom.get("severity", "high"),
                    title=anom.get("title", "Sender Envelope Anomaly"),
                    description=anom.get("description", "A sender address inconsistency was observed."),
                    evidence_reference="email_metadata.reply_to" if anom.get("code") == "REPLY_TO_MISMATCH" else "email_metadata.return_path",
                    weight=85 if anom.get("code") == "REPLY_TO_MISMATCH" else 60,
                )
            )

        # 2. Authentication Failures
        if auth.spf.status in ("fail", "softfail", "permerror"):
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="SPF_FAILURE",
                    severity="high" if auth.spf.status == "fail" else "medium",
                    title=f"SPF Verification {auth.spf.status.upper()}",
                    description=f"Sending mail server failed SPF policy check: {auth.spf.details or 'Sender not authorized in domain DNS'}",
                    evidence_reference="email_authentication.spf_status",
                    weight=75,
                )
            )

        if auth.dkim.status in ("fail", "permerror"):
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="DKIM_FAILURE",
                    severity="high",
                    title="DKIM Cryptographic Signature Invalid",
                    description=f"Digital cryptographic signature verification failed: {auth.dkim.details or 'Body hash does not verify'}",
                    evidence_reference="email_authentication.dkim_status",
                    weight=80,
                )
            )

        if auth.dmarc.status == "fail":
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="DMARC_FAILURE",
                    severity="high",
                    title="DMARC Alignment Policy Violated",
                    description="The message failed both SPF and DKIM alignment criteria defined by sender domain policy.",
                    evidence_reference="email_authentication.dmarc_status",
                    weight=85,
                )
            )

        # 3. Lookalike Domains (From URLs & Sender Envelope)
        for spoof_desc in domain_lookalikes:
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="LOOKALIKE_DOMAIN",
                    severity="critical",
                    title="Impersonation / Lookalike Domain Observed",
                    description=spoof_desc,
                    evidence_reference="email_indicators.domain",
                    weight=90,
                )
            )

        # 4. Dangerous / Suspicious URLs
        for u in urls:
            if u.is_ip_based:
                reasons.append(
                    AnalysisReasonSchema(
                        reason_code="IP_BASED_URL",
                        severity="high",
                        title="Direct IP URL Destination",
                        description=f"Hyperlink '{u.original_url[:60]}...' points directly to an IP address without domain resolution.",
                        evidence_reference=f"email_urls.{u.hostname}",
                        weight=70,
                    )
                )
            elif u.threat_level in ("high", "critical", "suspicious") or u.is_lookalike or u.risk_score >= 35:
                reasons.append(
                    AnalysisReasonSchema(
                        reason_code="SUSPICIOUS_URL",
                        severity="critical" if u.risk_score >= 70 else "high" if u.risk_score >= 45 else "medium",
                        title="High-Risk Embedded Hyperlink",
                        description=f"URL '{u.original_url[:60]}' flagged: {u.reason}",
                        evidence_reference="email_urls.risk_score",
                        weight=u.risk_score,
                    )
                )

        # 5. Attachment Threats
        for att in attachments:
            if att.is_double_extension or att.is_executable or att.is_suspicious:
                reasons.append(
                    AnalysisReasonSchema(
                        reason_code="SUSPICIOUS_ATTACHMENT",
                        severity="critical" if att.is_double_extension or att.is_executable else "high",
                        title=f"High-Risk Attachment Indicator: {att.filename}",
                        description=f"Payload metadata exhibits security risk signals: {'; '.join(att.detected_signals)} (SHA-256: {att.sha256[:16]}...). Static structural indicator; full sandbox execution required for confirmed weaponization.",
                        evidence_reference=f"email_attachments.{att.sha256}",
                        weight=95,
                    )
                )
                if att.is_double_extension:
                    reasons.append(
                        AnalysisReasonSchema(
                            reason_code="SUSPICIOUS_DOUBLE_EXTENSION",
                            severity="critical",
                            title=f"Deceptive Double-Extension Detected: {att.filename}",
                            description=f"Attachment '{att.filename}' masquerades as a standard document using double extension evasion.",
                            evidence_reference=f"email_attachments.{att.sha256}",
                            weight=98,
                        )
                    )

        # 6. Linguistic Intent & Behavioral Signals
        matches = linguistics.get("matches", {})

        if features.get("financial_request_score", 0.0) >= 0.2:
            kw_list = ", ".join(matches.get("financial", [])[:4])
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="FINANCIAL_REQUEST",
                    severity="high",
                    title="Wire / Financial Transfer Solicitation",
                    description=f"Message contains financial remittance / wire transfer keywords ({kw_list}).",
                    evidence_reference="email_metadata.body",
                    weight=85,
                )
            )

        if features.get("impersonation_score", 0.0) >= 0.2 or features.get("display_name_impersonation_signal", 0.0) >= 0.5:
            kw_list = ", ".join(matches.get("impersonation", [])[:4]) or "Executive Title"
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="EXECUTIVE_IMPERSONATION",
                    severity="high",
                    title="Executive / Authority Impersonation Indicator",
                    description=f"Message exhibits executive impersonation or confidential meeting pressure cues ({kw_list}).",
                    evidence_reference="email_metadata.from_display_name",
                    weight=80,
                )
            )

        if features.get("credential_request_score", 0.0) >= 0.2:
            kw_list = ", ".join(matches.get("credential", [])[:4])
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="CREDENTIAL_REQUEST",
                    severity="high",
                    title="Credential / Identity Harvesting Intent",
                    description=f"Message solicits authentication re-verification or credential entry ({kw_list}).",
                    evidence_reference="email_metadata.body",
                    weight=80,
                )
            )

        if features.get("urgency_score", 0.0) >= 0.2:
            kw_list = ", ".join(matches.get("urgency", [])[:4])
            reasons.append(
                AnalysisReasonSchema(
                    reason_code="URGENCY_LANGUAGE",
                    severity="medium",
                    title="Coercive Urgency & Pressure Tactics",
                    description=f"Message uses artificial urgency to prompt immediate compliance ({kw_list}).",
                    evidence_reference="email_metadata.body",
                    weight=60,
                )
            )

        return reasons

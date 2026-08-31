import pytest
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.findings import FindingsEngine
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailAuthenticationModel,
    EmailUrlModel,
    EmailAttachmentModel,
    AnalysisReasonModel,
)


def test_findings_engine_evidence_traceability():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-FND-001",
        filename="phishing_attack.eml",
        sha256="aabbccddeeff",
        status="completed",
        risk_score=92,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-FND-001",
        from_email="billing@legit-corp.com",
        from_domain="legit-corp.com",
        reply_to="payments@fraudster.xyz",
        subject="Urgent Payment Pending",
    )
    analysis.authentication = EmailAuthenticationModel(
        analysis_id="ANL-FND-001",
        spf_status="fail",
        spf_details="IP 185.220.101.5 is not authorized by legit-corp.com SPF record",
        dkim_status="fail",
        dkim_details="Body hash did not verify",
        dmarc_status="fail",
        dmarc_policy="quarantine",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id="ANL-FND-001",
            original_url="https://leglt-corp.xyz/login",
            normalized_url="https://leglt-corp.xyz/login",
            domain="leglt-corp.xyz",
            is_lookalike=True,
            risk_score=95,
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id="ANL-FND-001",
            filename="remittance_advice.pdf.exe",
            sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            is_executable=True,
            is_suspicious=True,
            is_double_extension=True,
        )
    ]
    analysis.reasons = [
        AnalysisReasonModel(
            analysis_id="ANL-FND-001",
            reason_code="URGENCY_SIGNAL",
            title="Urgent Language Detected",
            severity="high",
            description="Coercive payment urgency detected in email body.",
            evidence_reference="email_body:linguistic_analysis",
        )
    ]

    inv_id = "INV-FND-001"
    entities = EntityBuilder(analysis, inv_id).build_all_entities()
    relationships = RelationshipBuilder(analysis, inv_id, entities).build_all_relationships()
    findings_engine = FindingsEngine(analysis, inv_id, entities, relationships)
    findings = findings_engine.generate_findings()

    codes = [f["reason_code"] for f in findings]
    assert "REPLY_TO_MISMATCH" in codes
    assert "SPF_FAILURE" in codes
    assert "DKIM_FAILURE" in codes
    assert "DMARC_FAILURE" in codes
    assert "LOOKALIKE_DOMAIN" in codes
    assert "SUSPICIOUS_ATTACHMENT" in codes
    assert "URGENCY_SIGNAL" in codes

    # Ensure every finding has evidence references and linked entity IDs
    for f in findings:
        assert len(f["evidence_references"]) > 0
        assert len(f["entity_ids"]) > 0
        assert f["severity"] in ("low", "moderate", "medium", "high", "critical")
        assert 0.0 <= f["confidence"] <= 1.0

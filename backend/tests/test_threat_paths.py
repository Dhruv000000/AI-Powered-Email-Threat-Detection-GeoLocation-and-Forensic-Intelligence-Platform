import pytest
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.paths_engine import ThreatPathEngine
from app.services.investigation.summary_generator import (
    SummaryEngine,
    generate_investigation_summary,
)
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)


def test_threat_paths_discovery_all_four_patterns():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-PATH-001",
        filename="threat_sample.eml",
        sha256="1234567890abcdef",
        status="completed",
        threat_type="phishing",
        risk_score=90,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-PATH-001",
        from_header='"Security" <attacker@spoofed.xyz>',
        from_email="attacker@spoofed.xyz",
        from_domain="spoofed.xyz",
        reply_to="hijack@foreign-host.org",
        to_recipients=["user@corp.com"],
        subject="Invoice Notification",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id="ANL-PATH-001",
            original_url="https://portal.spoofed.xyz/view",
            normalized_url="https://portal.spoofed.xyz/view",
            domain="spoofed.xyz",
            is_lookalike=True,
            risk_score=95,
            threat_level="critical",
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id="ANL-PATH-001",
            filename="document.zip",
            sha256="9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
            is_suspicious=True,
        )
    ]
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id="ANL-PATH-001",
            hop_number=1,
            from_server="mail.origin-hop.net",
            ip="203.0.113.50",
            is_origin_node=True,
        )
    ]

    inv_id = "INV-PATH-001"
    entities = EntityBuilder(analysis, inv_id).build_all_entities()
    relationships = RelationshipBuilder(analysis, inv_id, entities).build_all_relationships()
    path_engine = ThreatPathEngine(analysis, inv_id, entities, relationships)
    paths = path_engine.compute_threat_paths()

    path_types = {p["path_type"] for p in paths}
    # 1. Credential Phishing Path
    assert "phishing_infrastructure_path" in path_types
    # 2. Malicious Attachment Delivery Path
    assert "malware_delivery_path" in path_types
    # 3. Origin Relay Trace Path
    assert any(pt in path_types for pt in ("origin_relay_path", "infrastructure_relay_path"))
    # 4. Sender Deception Path (Reply-To mismatch)
    assert "sender_deception_path" in path_types

    for p in paths:
        assert len(p["steps"]) >= 2
        assert len(p["node_ids"]) >= 2
        assert len(p["edge_ids"]) >= 1
        assert p["confidence"] > 0.0
        assert p["title"] != ""
        assert p["severity"] in ("low", "moderate", "medium", "high", "critical")
        assert p["description"] != ""


def test_summary_generator_narrative():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-SUMM-001",
        filename="phish.eml",
        sha256="aabbcc112233",
        status="completed",
        threat_type="phishing",
        risk_score=88,
        severity="high",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-SUMM-001",
        from_email="attacker@fake.xyz",
        subject="Password Reset",
        date_header="Tue, 01 Sep 2026 09:00:00 +0000",
    )

    inv_id = "INV-SUMM-001"
    entities = EntityBuilder(analysis, inv_id).build_all_entities()
    relationships = RelationshipBuilder(analysis, inv_id, entities).build_all_relationships()
    paths = ThreatPathEngine(analysis, inv_id, entities, relationships).compute_threat_paths()

    summary_engine = SummaryEngine(
        analysis=analysis,
        investigation_id=inv_id,
        entities=entities,
        findings=[{"severity": "high", "title": "Lookalike Domain"}],
        threat_paths=paths,
    )

    summary_dict = summary_engine.generate_summary()
    assert summary_dict["investigation_id"] == inv_id
    assert summary_dict["analysis_id"] == "ANL-SUMM-001"
    assert "executive_summary" in summary_dict
    assert "Phishing" in summary_dict["executive_summary"]
    assert "88/100" in summary_dict["executive_summary"]
    assert len(summary_dict["timeline"]) >= 1

    summary_str = generate_investigation_summary(
        threat_type="phishing",
        risk_score=88,
        severity="high",
        entity_count=5,
        threat_path_count=2,
        finding_count=1,
    )
    assert "88/100" in summary_str
    assert "5 distinct entities" in summary_str

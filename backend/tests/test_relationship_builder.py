import pytest
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)


def test_relationship_builder_provenance_and_vocabulary():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-REL-001",
        filename="bec_sample.eml",
        sha256="abc123sha256",
        status="completed",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-REL-001",
        from_email="ceo@executive-corp.com",
        from_domain="executive-corp.com",
        reply_to="attacker@financial-fraud.xyz",
        to_recipients=["accountant@enterprise.com"],
        subject="Wire Transfer Urgently Needed",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id="ANL-REL-001",
            original_url="https://secure-portal.xyz/login",
            normalized_url="https://secure-portal.xyz/login",
            domain="secure-portal.xyz",
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id="ANL-REL-001",
            filename="invoice.exe",
            sha256="def456sha256",
            is_executable=True,
        )
    ]
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id="ANL-REL-001",
            hop_number=1,
            from_server="relay.mailhost.xyz",
            ip="198.51.100.25",
            is_origin_node=True,
        )
    ]

    inv_id = "INV-REL-001"
    entities = EntityBuilder(analysis, inv_id).build_all_entities()
    rel_builder = RelationshipBuilder(analysis, inv_id, entities)
    relationships = rel_builder.build_all_relationships()

    rel_types = {r["type"] for r in relationships}
    assert "SENT" in rel_types
    assert "REPLIED_TO" in rel_types
    assert "DELIVERED_TO" in rel_types
    assert "LINKS_TO" in rel_types
    assert "USES_DOMAIN" in rel_types
    assert "OBSERVED_VIA" in rel_types
    assert "HAS_IP" in rel_types
    assert "HAS_ATTACHMENT" in rel_types
    assert "HAS_HASH" in rel_types

    # Validate provenance on every relationship
    for r in relationships:
        assert "provenance" in r
        assert r["provenance"] is not None
        assert "confidence" in r
        assert 0.0 <= r["confidence"] <= 1.0
        assert r["id"].startswith("rel:")

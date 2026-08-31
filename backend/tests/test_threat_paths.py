import pytest
from app.services.investigation.entity_builder import EntityBuilder
from app.services.investigation.relationship_builder import RelationshipBuilder
from app.services.investigation.paths import ThreatPathEngine
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)


def test_threat_paths_discovery():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-PATH-001",
        filename="threat_sample.eml",
        sha256="1234567890abcdef",
        status="completed",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-PATH-001",
        from_email="attacker@spoofed.xyz",
        subject="Invoice Notification",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id="ANL-PATH-001",
            original_url="https://portal.spoofed.xyz/view",
            normalized_url="https://portal.spoofed.xyz/view",
            domain="spoofed.xyz",
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
    assert "phishing_infrastructure_path" in path_types
    assert "malware_delivery_path" in path_types
    assert "origin_relay_path" in path_types

    for p in paths:
        assert len(p["steps"]) >= 2
        assert len(p["node_ids"]) >= 2
        assert len(p["edge_ids"]) >= 1
        assert p["confidence"] > 0.0

import pytest
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
)
from app.services.investigation.orchestrator import InvestigationOrchestrator
from app.graph.memory import InMemoryGraphStore


def _seed_completed_analysis(db_session, analysis_id="ANL-ORCH-001") -> EmailAnalysisModel:
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="phishing_wire.eml",
        sha256="99887766554433221100",
        status="completed",
        threat_type="phishing",
        risk_score=88,
        severity="high",
        ai_confidence=0.94,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="spoofed-exec@company.com",
        reply_to="fraud@attacker.xyz",
        subject="URGENT: Executive Wire Transfer Required",
        date_header="Fri, 29 Aug 2026 12:00:00 +0000",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="https://pay-verify.xyz/auth",
            normalized_url="https://pay-verify.xyz/auth",
            domain="pay-verify.xyz",
            is_lookalike=True,
            risk_score=92,
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id=analysis_id,
            filename="instructions.pdf.exe",
            sha256="fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
            is_executable=True,
            is_suspicious=True,
        )
    ]
    db_session.add(analysis)
    db_session.commit()
    return analysis


def test_investigation_orchestrator_lifecycle(db_session, memory_graph_store):
    analysis = _seed_completed_analysis(db_session, "ANL-ORCH-001")
    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)

    result = orchestrator.run_investigation("ANL-ORCH-001")

    assert result.investigation_id.startswith("INV-")
    assert result.status == "completed"
    assert result.stage == "completed"
    assert result.progress == 100
    assert result.threat_type == "phishing"
    assert result.risk_score == 88
    assert result.severity == "high"
    assert result.finding_count >= 2
    assert result.entity_count >= 4
    assert result.summary is not None
    assert len(result.summary.timeline) >= 2


def test_investigation_idempotency(db_session, memory_graph_store):
    analysis = _seed_completed_analysis(db_session, "ANL-ORCH-IDEMP")
    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)

    # First run
    res1 = orchestrator.run_investigation("ANL-ORCH-IDEMP")
    inv_id1 = res1.investigation_id
    initial_node_count = res1.entity_count

    # Second run without force
    res2 = orchestrator.run_investigation("ANL-ORCH-IDEMP", force_reinvestigation=False)
    inv_id2 = res2.investigation_id

    # Must be exact same investigation and no duplicates created
    assert inv_id1 == inv_id2
    assert res2.entity_count == initial_node_count

    graph = memory_graph_store.get_investigation_graph(inv_id1)
    assert graph["node_count"] == initial_node_count


def test_investigation_rejects_uncompleted_analysis(db_session, memory_graph_store):
    analysis = EmailAnalysisModel(
        analysis_id="ANL-ORCH-PENDING",
        filename="queued.eml",
        sha256="123456",
        status="processing", # Not completed
    )
    db_session.add(analysis)
    db_session.commit()

    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)
    with pytest.raises(ValueError, match="must be in 'completed' state"):
        orchestrator.run_investigation("ANL-ORCH-PENDING")


def test_investigation_handles_graph_failure_gracefully(db_session):
    analysis = _seed_completed_analysis(db_session, "ANL-ORCH-FAIL")

    class BrokenGraphStore(InMemoryGraphStore):
        def create_or_merge_nodes(self, nodes):
            raise ConnectionError("Simulated Neo4j network failure")

    broken_store = BrokenGraphStore()
    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=broken_store)

    with pytest.raises(ConnectionError):
        orchestrator.run_investigation("ANL-ORCH-FAIL")

    # Verify status in database was marked as failed
    inv_rec = orchestrator.inv_service.get_by_analysis_id("ANL-ORCH-FAIL")
    assert inv_rec is not None
    assert inv_rec.status == "failed"
    assert inv_rec.error_code == "NEO4J_UNAVAILABLE"

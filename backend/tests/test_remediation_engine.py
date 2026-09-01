import json
import pytest
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
)
from app.services.investigation.orchestrator import InvestigationOrchestrator
from app.services.integrations.remediation_runner import (
    RemediationRunnerService,
    execute_dns_swg_block,
    execute_mta_ip_blacklist,
    execute_exchange_purge,
    execute_edr_ioc_hunt,
    execute_identity_token_revoke,
)
from app.services.export.stix_exporter import STIX21Exporter
from app.services.investigation.report_service import DFIRReportService


def _seed_remediation_analysis(db_session, analysis_id="ANL-REMED-001") -> EmailAnalysisModel:
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="urgent_wire_payload.eml",
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        status="completed",
        threat_type="credential_phishing",
        risk_score=92,
        severity="critical",
        ai_confidence=0.96,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="spoofed-ceo@executive-pay.xyz",
        from_display_name="CEO John Doe",
        reply_to="attacker@c2-server.net",
        subject="URGENT: Executive Wire Transfer Authorization",
        message_id="<msg-wire-9988@executive-pay.xyz>",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="https://micr0soft-portal.xyz/login/auth",
            normalized_url="https://micr0soft-portal.xyz/login/auth",
            domain="micr0soft-portal.xyz",
            is_lookalike=True,
            risk_score=95,
        )
    ]
    analysis.ips = [
        EmailIpModel(
            analysis_id=analysis_id,
            ip="185.220.101.99",
            is_private=False,
            is_probable_origin=True,
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id=analysis_id,
            filename="Invoice_Wire_Instructions.pdf.exe",
            sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            is_executable=True,
            is_suspicious=True,
        )
    ]
    db_session.add(analysis)
    db_session.commit()
    return analysis


def test_remediation_connectors_standalone():
    # 1. DNS/SWG Connector
    dns_res = execute_dns_swg_block(["micr0soft-portal.xyz", "https://micr0soft-portal.xyz/login"])
    assert dns_res["status"] == "ENFORCED"
    assert dns_res["confirmation_id"].startswith("SWG-RULE-")
    assert dns_res["rollback_supported"] is True

    # 2. MTA IP Blacklist
    mta_res = execute_mta_ip_blacklist(["185.220.101.99"])
    assert mta_res["status"] == "ENFORCED"
    assert mta_res["confirmation_id"].startswith("MTA-ACL-")
    assert mta_res["firewall_action"] == "TCP_RESET_AND_DROP"

    # 3. Exchange Purge
    exch_res = execute_exchange_purge("<msg-wire-9988@executive-pay.xyz>", "URGENT Wire", "finance@target.com")
    assert exch_res["status"] == "PURGED"
    assert exch_res["items_purged"] >= 1
    assert exch_res["rollback_supported"] is False

    # 4. EDR Hunt
    edr_res = execute_edr_ioc_hunt(["11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"], ["185.220.101.99"])
    assert edr_res["status"] == "ISOLATED"
    assert edr_res["matching_endpoints_found"] >= 1
    assert len(edr_res["quarantined_hosts"]) >= 1

    # 5. Identity Token Revoke
    iam_res = execute_identity_token_revoke("finance-dept@target-corp.com")
    assert iam_res["status"] == "REVOKED"
    assert iam_res["active_refresh_tokens_revoked"] > 0


def test_remediation_runner_single_and_batch_execution(db_session, memory_graph_store):
    analysis_id = "ANL-REMED-RUNNER-01"
    _seed_remediation_analysis(db_session, analysis_id)

    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)
    inv = orchestrator.run_investigation(analysis_id)
    inv_id = inv.investigation_id

    runner = RemediationRunnerService(db_session)

    # 1. Single Action Execution (P0 DNS Block)
    res_single = runner.execute_action(
        target_id=inv_id,
        action_id="ACT-01",
        user_id="usr-soc-lead",
    )
    assert res_single.status == "SUCCESS"
    assert res_single.action_id == "ACT-01"
    assert res_single.target_system == "DNS / Secure Web Gateway"
    assert len(res_single.affected_indicators) >= 1
    assert res_single.rollback_supported is True

    # 2. Batch Execution of P0 Actions
    res_batch = runner.execute_batch(
        target_id=inv_id,
        priority_filter="P0",
        user_id="usr-soc-lead",
    )
    assert len(res_batch) >= 1
    assert all(r.status == "SUCCESS" for r in res_batch)

    # 3. History Retrieval
    history = runner.get_history(inv_id)
    assert history.total_executions >= 2
    assert history.active_enforcements >= 2
    assert len(history.logs) >= 2


def test_remediation_rollback_workflow(db_session, memory_graph_store):
    analysis_id = "ANL-REMED-ROLLBACK-01"
    _seed_remediation_analysis(db_session, analysis_id)

    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)
    inv = orchestrator.run_investigation(analysis_id)
    inv_id = inv.investigation_id

    runner = RemediationRunnerService(db_session)

    # Execute DNS block
    exec_res = runner.execute_action(target_id=inv_id, action_id="ACT-01")
    assert exec_res.status == "SUCCESS"

    # Rollback action
    rollback_res = runner.rollback_action(log_id=exec_res.log_id, user_id="usr-soc-lead")
    assert rollback_res.status == "REVERTED"
    assert rollback_res.reverted_at is not None
    assert rollback_res.execution_result.get("rollback_status") == "SUCCESSFULLY_DEACTIVATED"

    # Verify attempting double rollback raises 400 error
    with pytest.raises(Exception) as exc_info:
        runner.rollback_action(log_id=exec_res.log_id)
    assert "ALREADY_REVERTED" in str(exc_info.value) or "already been rolled back" in str(exc_info.value)


def test_stix_21_bundle_generation(db_session, memory_graph_store):
    analysis_id = "ANL-REMED-STIX-01"
    _seed_remediation_analysis(db_session, analysis_id)

    orchestrator = InvestigationOrchestrator(db=db_session, graph_store=memory_graph_store)
    inv = orchestrator.run_investigation(analysis_id)

    report_service = DFIRReportService(db_session)
    report_dto = report_service.generate_dfir_report(inv.investigation_id)

    exporter = STIX21Exporter(report_dto)
    bundle = exporter.export_stix_bundle()

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    objects = bundle["objects"]
    assert len(objects) >= 5

    # Verify object types present
    obj_types = {obj["type"] for obj in objects}
    assert "identity" in obj_types
    assert "observed-data" in obj_types
    assert "attack-pattern" in obj_types
    assert "indicator" in obj_types
    assert "course-of-action" in obj_types
    assert "relationship" in obj_types

    # Check indicator patterns
    indicators = [o for o in objects if o["type"] == "indicator"]
    for ind in indicators:
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert ind["id"].startswith("indicator--")

    # Check relationships
    relationships = [o for o in objects if o["type"] == "relationship"]
    for rel in relationships:
        assert rel["relationship_type"] in ("indicates", "mitigates")


def test_api_remediation_and_stix_endpoints(client, db_session):
    analysis_id = "ANL-REMED-API-01"
    _seed_remediation_analysis(db_session, analysis_id)

    # 1. Execute single remediation action via API
    resp_exec = client.post(
        f"/api/v1/investigations/{analysis_id}/remediation/execute",
        json={"action_id": "ACT-01", "dry_run": False},
    )
    assert resp_exec.status_code == 200
    exec_data = resp_exec.json()
    assert exec_data["status"] == "SUCCESS"
    assert exec_data["action_id"] == "ACT-01"
    log_id = exec_data["log_id"]

    # 2. Get history via API
    resp_hist = client.get(
        f"/api/v1/investigations/{analysis_id}/remediation/history",
    )
    assert resp_hist.status_code == 200
    hist_data = resp_hist.json()
    assert hist_data["total_executions"] >= 1

    # 3. Rollback via API
    resp_rb = client.post(
        f"/api/v1/investigations/{analysis_id}/remediation/{log_id}/rollback",
    )
    assert resp_rb.status_code == 200
    rb_data = resp_rb.json()
    assert rb_data["status"] == "REVERTED"

    # 4. Export STIX 2.1 Bundle via API
    resp_stix = client.get(
        f"/api/v1/investigations/{analysis_id}/export/stix",
    )
    assert resp_stix.status_code == 200
    assert "attachment; filename=" in resp_stix.headers.get("content-disposition", "")
    assert "AEGIS_STIX_" in resp_stix.headers.get("content-disposition", "")
    stix_bundle = resp_stix.json()
    assert stix_bundle["type"] == "bundle"
    assert len(stix_bundle["objects"]) >= 4

import pytest
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
)


def _seed_api_analysis(db_session, analysis_id="ANL-API-001"):
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="api_sample.eml",
        sha256="abcdef1234567890",
        status="completed",
        threat_type="phishing",
        risk_score=85,
        severity="high",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="alert@paypal-login.xyz",
        reply_to="attacker@darkhost.xyz",
        subject="Account Verification Required",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="https://paypal-login.xyz/auth",
            normalized_url="https://paypal-login.xyz/auth",
            domain="paypal-login.xyz",
            is_lookalike=True,
            risk_score=90,
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id=analysis_id,
            filename="statement.pdf.exe",
            sha256="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            is_executable=True,
        )
    ]
    db_session.add(analysis)
    db_session.commit()
    return analysis


def test_investigation_api_endpoints(client, db_session):
    _seed_api_analysis(db_session, "ANL-API-001")

    # 1. POST /api/v1/investigations
    res_post = client.post(
        "/api/v1/investigations",
        json={"analysis_id": "ANL-API-001", "mode": "direct"},
    )
    assert res_post.status_code == 200
    inv_data = res_post.json()
    assert "investigation_id" in inv_data
    inv_id = inv_data["investigation_id"]
    assert inv_data["status"] == "completed"
    assert inv_data["threat_type"] == "phishing"

    # 2. GET /api/v1/investigations
    res_list = client.get("/api/v1/investigations")
    assert res_list.status_code == 200
    list_json = res_list.json()
    assert list_json["total"] >= 1
    assert any(item["investigation_id"] == inv_id for item in list_json["items"])

    # 3. GET /api/v1/investigations/{id}
    res_get = client.get(f"/api/v1/investigations/{inv_id}")
    assert res_get.status_code == 200
    assert res_get.json()["investigation_id"] == inv_id

    # 4. GET /api/v1/investigations/{id}/status
    res_status = client.get(f"/api/v1/investigations/{inv_id}/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] == "completed"
    assert res_status.json()["progress"] == 100

    # 5. GET /api/v1/investigations/{id}/findings
    res_findings = client.get(f"/api/v1/investigations/{inv_id}/findings")
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 1
    assert any(f["reason_code"] == "REPLY_TO_MISMATCH" for f in findings)

    # 6. GET /api/v1/investigations/{id}/graph
    res_graph = client.get(f"/api/v1/investigations/{inv_id}/graph")
    assert res_graph.status_code == 200
    graph = res_graph.json()
    assert graph["node_count"] >= 3
    assert graph["edge_count"] >= 2
    assert "nodes" in graph
    assert "edges" in graph

    # 7. GET /api/v1/investigations/{id}/entities/{entity_id}
    entity_id = graph["nodes"][0]["data"]["id"]
    res_ent = client.get(f"/api/v1/investigations/{inv_id}/entities/{entity_id}")
    assert res_ent.status_code == 200
    assert res_ent.json()["entity_id"] == entity_id

    # 8. GET /api/v1/investigations/{id}/entities/{entity_id}/neighbors
    res_neigh = client.get(f"/api/v1/investigations/{inv_id}/entities/{entity_id}/neighbors")
    assert res_neigh.status_code == 200
    assert "nodes" in res_neigh.json()

    # 9. GET /api/v1/investigations/{id}/paths
    res_paths = client.get(f"/api/v1/investigations/{inv_id}/paths")
    assert res_paths.status_code == 200
    paths = res_paths.json()
    assert paths["total_paths"] >= 1

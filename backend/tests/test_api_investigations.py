import pytest
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailAttachmentModel,
    EmailIpModel,
)


def _seed_api_analysis(db_session, analysis_id="ANL-API-001", status="completed"):
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="api_sample.eml",
        sha256="abcdef1234567890",
        status=status,
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
    assert graph["node_count"] >= 5
    assert graph["edge_count"] >= 4
    assert len(graph["nodes"]) >= 5
    assert len(graph["edges"]) >= 4
    assert "nodes" in graph
    assert "edges" in graph
    for n in graph["nodes"]:
        assert "data" in n
        assert "id" in n["data"]
    for e in graph["edges"]:
        assert "data" in e
        assert "source" in e["data"]
        assert "target" in e["data"]

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


def test_investigation_api_error_handling(client, db_session):
    # Test 404 for nonexistent analysis
    res_404 = client.post(
        "/api/v1/investigations",
        json={"analysis_id": "ANL-NONEXISTENT-999"},
    )
    assert res_404.status_code == 404

    # Test 400 for analysis not in completed status
    _seed_api_analysis(db_session, "ANL-API-PROCESSING", status="processing")
    res_400 = client.post(
        "/api/v1/investigations",
        json={"analysis_id": "ANL-API-PROCESSING"},
    )
    assert res_400.status_code == 400

    # Test 404 for nonexistent investigation
    res_inv_404 = client.get("/api/v1/investigations/INV-NONEXISTENT")
    assert res_inv_404.status_code == 404


def test_get_graph_returns_all_extracted_entities_and_edges(client, db_session):
    analysis_id = "ANL-RECON-001"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="recon_test.eml",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="completed",
        threat_type="phishing",
        risk_score=92,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="security@micr0soft.com",
        from_header="security@micr0soft.com",
        reply_to="attacker@evil.com",
        subject="Urgent Security Alert",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="http://1.2.3.4/login",
            normalized_url="http://1.2.3.4/login",
            domain="1.2.3.4",
            is_ip_based=True,
            risk_score=95,
        )
    ]
    analysis.ips = [
        EmailIpModel(
            analysis_id=analysis_id,
            ip="1.2.3.4",
            ip_version=4,
            is_private=False,
            source="received_header",
            is_probable_origin=True,
        )
    ]
    db_session.add(analysis)
    db_session.commit()

    # Trigger investigation
    res_post = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"},
    )
    assert res_post.status_code == 200
    inv_id = res_post.json()["investigation_id"]

    # Call GET /api/v1/investigations/{investigation_id}/graph
    res_graph = client.get(f"/api/v1/investigations/{inv_id}/graph")
    assert res_graph.status_code == 200
    graph = res_graph.json()

    # Assert len(nodes) >= 5 and len(edges) >= 4
    nodes = graph["nodes"]
    edges = graph["edges"]
    assert len(nodes) >= 5, f"Expected at least 5 nodes, got {len(nodes)}: {nodes}"
    assert len(edges) >= 4, f"Expected at least 4 edges, got {len(edges)}: {edges}"

    # Verify expected node types exist
    node_types = {n["data"]["type"] for n in nodes}
    assert "Email" in node_types
    assert "EmailAddress" in node_types
    assert "URL" in node_types

    # Verify expected edge labels exist
    edge_labels = {e["data"]["label"] for e in edges}
    assert "SENT" in edge_labels
    assert "SPECIFIED_AS_REPLY_TO" in edge_labels
    assert "CONTAINS_URL" in edge_labels


def test_create_investigation_twice_is_idempotent(client, db_session):
    analysis_id = "ANL-IDEMPOTENT-001"
    _seed_api_analysis(db_session, analysis_id, status="completed")

    # 1. First Trigger
    res1 = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"},
    )
    assert res1.status_code == 200
    data1 = res1.json()
    inv_id1 = data1["investigation_id"]

    # 2. Second Trigger (Default Idempotent Return)
    res2 = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"},
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["investigation_id"] == inv_id1

    # 3. Third Trigger (Forced Reinvestigation)
    res3 = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "force_reinvestigation": True, "mode": "direct"},
    )
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["investigation_id"] == inv_id1

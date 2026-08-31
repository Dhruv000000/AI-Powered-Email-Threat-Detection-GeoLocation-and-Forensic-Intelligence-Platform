import pytest
from pathlib import Path


def test_end_to_end_investigation_flow(client, fixtures_dir):
    fixture_path = fixtures_dir / "phishing_credential_harvest.eml"
    with open(fixture_path, "rb") as f:
        file_bytes = f.read()

    # Step 1: Upload EML and run Task 01 Analysis
    res_anl = client.post(
        "/api/v1/email-analysis/analyze",
        files={"file": ("phishing_credential_harvest.eml", file_bytes, "message/rfc822")},
        data={"mode": "direct"},
    )
    assert res_anl.status_code == 200
    anl_data = res_anl.json()
    analysis_id = anl_data["analysis_id"]
    assert anl_data["status"] == "completed"

    # Step 2: Trigger Task 02 Investigation
    res_inv = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"},
    )
    assert res_inv.status_code == 200
    inv_data = res_inv.json()
    investigation_id = inv_data["investigation_id"]
    assert inv_data["status"] == "completed"
    assert inv_data["analysis_id"] == analysis_id

    # Step 3: Fetch Graph and verify topology
    res_graph = client.get(f"/api/v1/investigations/{investigation_id}/graph")
    assert res_graph.status_code == 200
    graph = res_graph.json()
    node_types = {n["data"]["type"] for n in graph["nodes"]}
    edge_labels = {e["data"]["label"] for e in graph["edges"]}

    assert "Email" in node_types
    assert "EmailAddress" in node_types
    assert "URL" in node_types or "Domain" in node_types
    assert "SENT" in edge_labels or "LINKS_TO" in edge_labels or "USES_DOMAIN" in edge_labels

    # Step 4: Fetch Findings and verify links to real evidence
    res_fnd = client.get(f"/api/v1/investigations/{investigation_id}/findings")
    assert res_fnd.status_code == 200
    findings = res_fnd.json()
    assert len(findings) > 0
    for fnd in findings:
        assert len(fnd["evidence_references"]) > 0
        assert len(fnd["entity_ids"]) > 0

    # Step 5: Fetch Threat Paths
    res_paths = client.get(f"/api/v1/investigations/{investigation_id}/paths")
    assert res_paths.status_code == 200
    paths = res_paths.json()
    assert "paths" in paths

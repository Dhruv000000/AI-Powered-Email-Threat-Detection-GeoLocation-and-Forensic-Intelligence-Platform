import pytest
from pathlib import Path

def test_analyze_uploaded_eml(client, fixtures_dir):
    fixture_path = fixtures_dir / "phishing_credential_harvest.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email-analysis/analyze",
            files={"file": ("phishing_credential_harvest.eml", f, "message/rfc822")},
            data={"mode": "direct"}
        )

    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["status"] == "completed"
    assert data["classification"]["threat_type"] in ("phishing", "suspicious", "business_email_compromise")
    assert data["classification"]["risk_score"] > 60
    assert data["evidence"]["sha256"] is not None
    assert len(data["relay_path"]) >= 1
    assert len(data["reasons"]) > 0

    analysis_id = data["analysis_id"]

    # Test GET /{analysis_id}
    res_get = client.get(f"/api/v1/email-analysis/{analysis_id}")
    assert res_get.status_code == 200
    assert res_get.json()["analysis_id"] == analysis_id

    # Test GET /{analysis_id}/status
    res_status = client.get(f"/api/v1/email-analysis/{analysis_id}/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] == "completed"
    assert res_status.json()["progress"] == 100

    # Test GET /{analysis_id}/indicators
    res_ind = client.get(f"/api/v1/email-analysis/{analysis_id}/indicators")
    assert res_ind.status_code == 200
    assert "ips" in res_ind.json()
    assert "urls" in res_ind.json()

    # Test GET /{analysis_id}/evidence
    res_ev = client.get(f"/api/v1/email-analysis/{analysis_id}/evidence")
    assert res_ev.status_code == 200
    assert res_ev.json()["sha256"] == data["evidence"]["sha256"]

def test_analyze_raw_email(client):
    raw_payload = """From: CEO <ceo@company.com>
To: accountant@company.com
Reply-To: fraud@external-attacker.xyz
Subject: URGENT: Wire Transfer $50,000 Immediately
Date: Fri, 29 Aug 2026 12:00:00 +0000

Michael, wire $50,000 to the escrow account today immediately.
"""
    response = client.post(
        "/api/v1/email-analysis/analyze-raw",
        json={"raw_content": raw_payload, "filename": "pasted_bec.eml"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["classification"]["threat_type"] == "business_email_compromise"
    assert data["classification"]["risk_score"] >= 50
    assert any(r["reason_code"] == "REPLY_TO_MISMATCH" for r in data["reasons"])

def test_idempotency_duplicate_upload(client, fixtures_dir):
    fixture_path = fixtures_dir / "benign_executive.eml"
    with open(fixture_path, "rb") as f:
        file_bytes = f.read()

    # First upload
    res1 = client.post(
        "/api/v1/email-analysis/analyze",
        files={"file": ("benign.eml", file_bytes, "message/rfc822")},
    )
    assert res1.status_code == 200
    id1 = res1.json()["analysis_id"]

    # Second upload (same bytes, force_reanalysis=False)
    res2 = client.post(
        "/api/v1/email-analysis/analyze",
        files={"file": ("benign.eml", file_bytes, "message/rfc822")},
        data={"force_reanalysis": "false"}
    )
    assert res2.status_code == 200
    id2 = res2.json()["analysis_id"]

    # Idempotent match returns exact same analysis record
    assert id1 == id2

def test_malformed_email_payload(client):
    response = client.post(
        "/api/v1/email-analysis/analyze-raw",
        json={"raw_content": "   "}
    )
    assert response.status_code == 400
    assert "error" in response.json()
    assert response.json()["error"]["code"] == "INVALID_EMAIL_PAYLOAD"

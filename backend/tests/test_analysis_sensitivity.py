import pytest
import hashlib
from fastapi.testclient import TestClient

TEST_A_BENIGN = """From: Rahul Sharma <rahul@example.com>
To: team@example.com
Subject: Meeting Tomorrow

Hi Team,

Just a reminder that our project meeting is scheduled for tomorrow at 10:00 AM.

Please bring the latest project updates.

Regards,
Rahul
"""

TEST_B_PHISHING = """From: Microsoft Security <security@micr0soft-security.example>
To: user@example.com
Subject: Urgent: Your Account Will Be Suspended

Your Microsoft account has been detected with unusual activity.

You must verify your account immediately.

Click here to verify your password:
https://micr0soft-security.example/login

Failure to verify within 24 hours will result in permanent account suspension.

Regards,
Microsoft Security Team
"""

TEST_C_BEC = """From: CEO <ceo@example.com>
To: finance@example.com
Subject: Urgent Wire Transfer

I am currently in a meeting and need you to process a confidential wire transfer immediately.

Please send $48,500 to the following account today.

Do not discuss this request with anyone else.

Regards,
CEO
"""

TEST_D_MALWARE = """From: billing@example.com
To: employee@example.com
Subject: Invoice Attached
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain

Please review the attached invoice.

--BOUNDARY123
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
--BOUNDARY123--
"""


def test_benign_email_low_risk(client: TestClient):
    res = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_A_BENIGN})
    assert res.status_code == 200
    data = res.json()
    assert data["classification"]["threat_type"] == "benign"
    assert data["classification"]["risk_score"] <= 15
    assert data["classification"]["severity"] == "low"


def test_credential_phishing_high_risk(client: TestClient):
    res = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_B_PHISHING})
    assert res.status_code == 200
    data = res.json()
    assert data["classification"]["threat_type"] == "phishing"
    assert data["classification"]["risk_score"] >= 55
    assert data["classification"]["severity"] in ("medium", "high", "critical")
    
    codes = [r["reason_code"] for r in data["reasons"]]
    assert any(c in codes for c in ("LOOKALIKE_DOMAIN", "CREDENTIAL_REQUEST", "URGENCY_LANGUAGE", "SUSPICIOUS_URL"))


def test_bec_financial_fraud_high_risk(client: TestClient):
    res = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_C_BEC})
    assert res.status_code == 200
    data = res.json()
    assert data["classification"]["threat_type"] == "business_email_compromise"
    assert data["classification"]["risk_score"] >= 35
    assert data["classification"]["severity"] in ("moderate", "medium", "high", "critical")

    codes = [r["reason_code"] for r in data["reasons"]]
    assert "FINANCIAL_REQUEST" in codes or "EXECUTIVE_IMPERSONATION" in codes


def test_malicious_attachment_high_risk(client: TestClient):
    res = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_D_MALWARE})
    assert res.status_code == 200
    data = res.json()
    assert data["classification"]["threat_type"] == "malicious_attachment"
    assert data["classification"]["risk_score"] >= 30
    assert data["classification"]["severity"] in ("moderate", "medium", "high", "critical")

    codes = [r["reason_code"] for r in data["reasons"]]
    assert "SUSPICIOUS_ATTACHMENT" in codes


def test_directional_risk_properties(client: TestClient):
    res_a = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_A_BENIGN})
    res_b = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_B_PHISHING})
    res_c = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_C_BEC})
    res_d = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_D_MALWARE})

    data_a = res_a.json()
    data_b = res_b.json()
    data_c = res_c.json()
    data_d = res_d.json()

    # Directional risk assertions
    assert data_b["classification"]["risk_score"] > data_a["classification"]["risk_score"]
    assert data_c["classification"]["risk_score"] > data_a["classification"]["risk_score"]
    assert data_d["classification"]["risk_score"] > data_a["classification"]["risk_score"]

    # Evidence hashes and unique analysis IDs
    assert data_a["evidence"]["sha256"] != data_b["evidence"]["sha256"]
    assert data_b["evidence"]["sha256"] != data_c["evidence"]["sha256"]


def test_same_email_is_deterministic(client: TestClient):
    res_1 = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_B_PHISHING, "force_reanalysis": True})
    res_2 = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": TEST_B_PHISHING, "force_reanalysis": True})

    data_1 = res_1.json()
    data_2 = res_2.json()

    assert data_1["classification"]["threat_type"] == data_2["classification"]["threat_type"]
    assert data_1["classification"]["risk_score"] == data_2["classification"]["risk_score"]
    assert data_1["classification"]["ai_confidence"] == data_2["classification"]["ai_confidence"]


def test_edge_cases_and_missing_headers(client: TestClient):
    # Minimal email without headers
    res_min = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": "Just a plain body text without headers."})
    assert res_min.status_code == 200
    assert res_min.json()["classification"]["risk_score"] <= 20

    # HTML with script injection attempt
    html_email = """From: tester@domain.com
Subject: Test HTML
Content-Type: text/html

<html><body><script>alert('xss')</script><p>Hello safe world</p></body></html>
"""
    res_html = client.post("/api/v1/email-analysis/analyze-raw", json={"raw_content": html_email})
    assert res_html.status_code == 200
    assert res_html.json()["classification"]["risk_score"] <= 20

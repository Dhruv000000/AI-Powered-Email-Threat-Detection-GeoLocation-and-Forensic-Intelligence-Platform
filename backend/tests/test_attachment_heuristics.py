import pytest
from app.services.ai.narrative_generator import get_target_domain, synthesize_narrative


def test_get_target_domain_prioritizes_high_risk_and_parses_clean_domain():
    urls = [
        {"url": "https://cdn.legit.com/style.css", "risk_score": 10, "threat_level": "clean"},
        {"url": "http://customs-port-release-auth.com/verify?id=99", "risk_score": 85, "threat_level": "high"},
    ]
    domain = get_target_domain(urls)
    assert domain == "customs-port-release-auth.com"

    # Single plain URL string test
    plain_urls = [{"url": "http://customs-port-release-auth.com/verify"}]
    assert get_target_domain(plain_urls) == "customs-port-release-auth.com"


def test_attachment_heuristic_fallback_and_dynamic_target_domain(client, db_session):
    # 1. Supply raw plaintext sample containing: Attachment: customs_invoice_release.pdf.exe
    # and extracted URL: http://customs-port-release-auth.com/verify
    raw_email_text = (
        "From: notifications@customs-clearance.net\n"
        "To: target@victim.org\n"
        "Subject: Urgent: Customs Invoice Clearance Required\n"
        "Date: Wed, 02 Sep 2026 10:00:00 +0000\n\n"
        "Your import consignment has arrived at the terminal.\n"
        "Please verify your credentials immediately at: http://customs-port-release-auth.com/verify\n\n"
        "Attachment: customs_invoice_release.pdf.exe\n"
    )

    response = client.post(
        "/api/v1/email-analysis/analyze-raw",
        json={"raw_content": raw_email_text}
    )
    assert response.status_code == 200
    analysis_data = response.json()
    analysis_id = analysis_data["analysis_id"]

    # Verify attachments extracted via plaintext fallback
    extracted_attachments = analysis_data.get("attachments") or analysis_data.get("indicators", {}).get("attachments", [])
    assert len(extracted_attachments) >= 1
    att = extracted_attachments[0]
    assert att["filename"] == "customs_invoice_release.pdf.exe"
    assert att["is_double_extension"] is True
    assert att["is_executable"] is True

    # 2. Trigger investigation for this analysis
    inv_response = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"}
    )
    assert inv_response.status_code == 200
    inv_id = inv_response.json()["investigation_id"]

    # 3. Retrieve investigation summary
    summ_response = client.get(f"/api/v1/investigations/{inv_id}")
    assert summ_response.status_code == 200
    inv_detail = summ_response.json()
    summary = inv_detail.get("summary") or {}

    # Retrieve investigation findings
    findings_response = client.get(f"/api/v1/investigations/{inv_id}/findings")
    assert findings_response.status_code == 200
    res_data = findings_response.json()
    findings = res_data if isinstance(res_data, list) else res_data.get("items", [])

    # Assert 1: AI narrative summary explicitly references customs-port-release-auth.com
    executive_summary = summary.get("executive_summary", "")
    assert "customs-port-release-auth.com" in executive_summary

    # Assert 2: attachments_count >= 1 and malicious_attachments_count >= 1
    assert summary.get("attachments_count", 0) >= 1
    assert summary.get("malicious_attachments_count", 0) >= 1

    # Assert 3: Finding SUSPICIOUS_DOUBLE_EXTENSION is generated
    double_ext_finding = [
        f for f in findings
        if f.get("finding_code") == "SUSPICIOUS_DOUBLE_EXTENSION"
        or f.get("reason_code") == "SUSPICIOUS_DOUBLE_EXTENSION"
        or "SUSPICIOUS_DOUBLE_EXTENSION" in f.get("finding_id", "")
    ]
    assert len(double_ext_finding) >= 1

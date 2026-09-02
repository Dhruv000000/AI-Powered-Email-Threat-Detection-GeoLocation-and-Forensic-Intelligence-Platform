import pytest
from app.services.ai.summary_generator import (
    extract_primary_target_domain,
    generate_canonical_soc_summary,
)


def test_extract_primary_target_domain():
    urls = [
        {"url": "https://cdn.legit.com/banner.png", "risk_score": 5, "threat_level": "clean"},
        {"url": "https://tax-audit-resolution-gateway.com/irs-portal/auth", "risk_score": 85, "threat_level": "high"},
    ]
    domain = extract_primary_target_domain(urls)
    assert domain == "tax-audit-resolution-gateway.com"


def test_generate_canonical_soc_summary_domain_extraction():
    sample_data = {
        "email": {
            "from_email": "notice@irs-tax-alert.org",
            "from_display_name": "IRS Tax Audit Division",
            "from_domain": "irs-tax-alert.org",
            "reply_to": "attacker-collector@darkhost.xyz",
        },
        "classification": {
            "threat_type": "phishing",
            "risk_score": 88,
            "severity": "high",
        },
        "indicators": {
            "urls": [
                {
                    "url": "https://tax-audit-resolution-gateway.com/irs-portal/auth",
                    "domain": "tax-audit-resolution-gateway.com",
                    "risk_score": 90,
                    "threat_level": "critical",
                }
            ]
        },
        "relay_path": [
            {
                "ip": "198.51.100.42",
                "location": {
                    "country_name": "United States",
                    "as_org": "Cloudflare Bulletproof Proxy Layer",
                    "is_tor": False,
                }
            }
        ],
    }

    summary = generate_canonical_soc_summary(sample_data)
    assert "tax-audit-resolution-gateway.com" in summary
    assert "portal-verification-service-auth.com" not in summary
    assert "IRS Tax Audit Division" in summary


def test_analysis_and_investigation_summary_consistency(client, db_session):
    # Ingest a sample containing tax-audit-resolution-gateway.com
    raw_email_text = (
        "From: IRS Tax Compliance <notice@irs-tax-alert.org>\n"
        "To: target-executive@enterprise.com\n"
        "Subject: Urgent: Tax Audit Discrepancy Notice #90412\n"
        "Date: Thu, 03 Sep 2026 09:00:00 +0000\n\n"
        "Immediate response required for pending corporate audit reconciliation.\n"
        "Access the resolution gateway: https://tax-audit-resolution-gateway.com/irs-portal/auth\n"
    )

    response = client.post(
        "/api/v1/email-analysis/analyze-raw",
        json={"raw_content": raw_email_text}
    )
    assert response.status_code == 200
    analysis_data = response.json()
    analysis_id = analysis_data["analysis_id"]

    # 1. Assert Analyze view payload contains tax-audit-resolution-gateway.com
    ai_summary = analysis_data.get("ai_summary") or analysis_data.get("classification", {}).get("ai_summary", "")
    assert "tax-audit-resolution-gateway.com" in ai_summary
    assert "portal-verification-service-auth.com" not in str(analysis_data)

    # 2. Trigger DFIR Investigation
    inv_response = client.post(
        "/api/v1/investigations",
        json={"analysis_id": analysis_id, "mode": "direct"}
    )
    assert inv_response.status_code == 200
    inv_id = inv_response.json()["investigation_id"]

    # 3. Assert DFIR Investigation summary contains tax-audit-resolution-gateway.com
    inv_detail_res = client.get(f"/api/v1/investigations/{inv_id}")
    assert inv_detail_res.status_code == 200
    inv_detail = inv_detail_res.json()
    inv_summary = (inv_detail.get("summary") or {}).get("executive_summary", "")

    assert "tax-audit-resolution-gateway.com" in inv_summary
    assert "portal-verification-service-auth.com" not in str(inv_detail)

    # 4. Generate DFIR Report and assert narrative consistency
    report_res = client.post(
        "/api/v1/reports/generate",
        json={"investigation_id": inv_id}
    )
    if report_res.status_code == 200:
        report_data = report_res.json()
        report_narrative = (report_data.get("executive_summary") or {}).get("narrative", "")
        assert "tax-audit-resolution-gateway.com" in report_narrative
        assert "portal-verification-service-auth.com" not in report_narrative

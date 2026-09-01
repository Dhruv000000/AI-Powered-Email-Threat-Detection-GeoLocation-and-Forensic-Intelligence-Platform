import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailAuthenticationModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)
from app.db.models.investigation import InvestigationModel


def test_dfir_report_json_generation_with_investigation_and_analysis_id(client: TestClient, db_session):
    analysis_id = "ANL-RPT-001"
    inv_id = "INV-RPT-001"

    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="phish_report_sample.eml",
        sha256="aabbccddee11223344556677889900aabbccddee11223344556677889900aabb",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="phishing",
        risk_score=92,
        severity="critical",
        ai_confidence=0.96,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="security-update@micr0soft-portal.xyz",
        from_display_name="Microsoft Security Authority",
        to_recipients=["victim.corp@target.org"],
        reply_to="attacker-harvest@darkdomain.cc",
        subject="Action Required: Re-verify your Microsoft 365 Account",
        date_header="Tue, 01 Sep 2026 20:00:00 +0000",
    )
    analysis.authentication = EmailAuthenticationModel(
        analysis_id=analysis_id,
        spf_status="fail",
        dkim_status="fail",
        dmarc_status="fail",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="http://micr0soft-portal.xyz/login?session=481029",
            normalized_url="http://micr0soft-portal.xyz/login?session=481029",
            domain="micr0soft-portal.xyz",
            risk_score=95,
            threat_level="suspicious",
        )
    ]
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=1,
            from_server="tor-exit.zwiebelfreunde.de",
            by_server="mail.origin.org",
            ip="185.220.101.99",
            protocol="ESMTP",
            delay_seconds=0,
            is_origin_node=True,
            raw_header="Received: from tor-exit.zwiebelfreunde.de (185.220.101.99) by mail.origin.org",
        )
    ]

    inv = InvestigationModel(
        investigation_id=inv_id,
        analysis_id=analysis_id,
        status="completed",
        summary="Forensic test",
        node_count=10,
        edge_count=15,
        threat_path_count=2,
    )

    db_session.add(analysis)
    db_session.add(inv)
    db_session.commit()

    # 1. Fetch report by investigation_id
    res_inv = client.get(f"/api/v1/investigations/{inv_id}/report")
    assert res_inv.status_code == 200
    report_data = res_inv.json()
    assert report_data["investigation_id"] == inv_id
    assert report_data["analysis_id"] == analysis_id
    assert report_data["executive_summary"]["verdict"] == "MALICIOUS"
    assert report_data["executive_summary"]["risk_score"] == 92
    assert len(report_data["mitre_matrix"]) >= 2
    assert len(report_data["remediation_plan"]) >= 4
    assert len(report_data["iocs"]) >= 3

    # 2. Fetch report by analysis_id directly (identifier flexibility)
    res_anl = client.get(f"/api/v1/investigations/{analysis_id}/report")
    assert res_anl.status_code == 200
    assert res_anl.json()["analysis_id"] == analysis_id


def test_mitre_attack_technique_mapping(client: TestClient, db_session):
    analysis_id = "ANL-MITRE-002"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="mitre_test.eml",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="phishing",
        risk_score=95,
        severity="critical",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="ceo@executive-spoof.org",
        from_display_name="Chief Executive Officer",
        reply_to="attacker@financial-fraud.xyz",
        subject="Wire Instruction Confirmation",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="https://portal-login-verify.com/auth",
            normalized_url="https://portal-login-verify.com/auth",
            domain="portal-login-verify.com",
            risk_score=90,
            threat_level="suspicious",
        )
    ]
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id=analysis_id,
            hop_number=1,
            from_server="tor-node-01.nl",
            by_server="mail.origin.org",
            ip="185.220.101.99",
            protocol="ESMTP",
            delay_seconds=0,
            is_origin_node=True,
            raw_header="Received: from tor-node-01.nl (185.220.101.99) by mail.origin.org",
        )
    ]
    db_session.add(analysis)
    db_session.commit()

    res = client.get(f"/api/v1/investigations/{analysis_id}/report")
    assert res.status_code == 200
    data = res.json()
    technique_ids = [m["technique_id"] for m in data["mitre_matrix"]]

    # Spearphishing Link (T1566.002)
    assert "T1566.002" in technique_ids
    # Impersonation (T1656)
    assert "T1656" in technique_ids
    # Reply-To Email Account Deception (T1586.002)
    assert "T1586.002" in technique_ids
    # Multi-hop Proxy Tor (T1090.003)
    assert "T1090.003" in technique_ids


def test_pdf_export_endpoint(client: TestClient, db_session):
    analysis_id = "ANL-PDF-003"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="pdf_test.eml",
        sha256="feedbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="phishing",
        risk_score=85,
        severity="high",
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="admin@secure-verify.net",
        subject="Important Account Notice",
    )
    db_session.add(analysis)
    db_session.commit()

    # Call PDF export endpoint
    res = client.get(f"/api/v1/investigations/{analysis_id}/export/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in res.headers["content-disposition"]
    
    # Assert valid PDF binary stream
    content = res.content
    assert len(content) > 1000
    assert content.startswith(b"%PDF-")


def test_ioc_json_and_csv_export_endpoints(client: TestClient, db_session):
    analysis_id = "ANL-IOC-004"
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="ioc_test.eml",
        sha256="cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678",
        status="completed",
        probable_origin_ip="185.220.101.99",
        threat_type="phishing",
        risk_score=75,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="bad@malicious-sender.com",
        reply_to="reply@malicious-divert.com",
        subject="Urgent Invoice",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id=analysis_id,
            original_url="http://malicious-divert.com/invoice.pdf",
            normalized_url="http://malicious-divert.com/invoice.pdf",
            domain="malicious-divert.com",
            risk_score=80,
            threat_level="suspicious",
        )
    ]
    db_session.add(analysis)
    db_session.commit()

    # JSON export
    res_json = client.get(f"/api/v1/investigations/{analysis_id}/export/iocs?format=json")
    assert res_json.status_code == 200
    json_data = res_json.json()
    assert json_data["total_iocs"] >= 3

    # CSV export
    res_csv = client.get(f"/api/v1/investigations/{analysis_id}/export/iocs?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    csv_text = res_csv.text
    assert "Type,Indicator Value,Severity,Killchain Stage,Threat Context" in csv_text
    assert "malicious-divert.com" in csv_text

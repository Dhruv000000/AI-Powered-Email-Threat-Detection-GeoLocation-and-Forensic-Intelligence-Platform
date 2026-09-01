import pytest
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
)
from app.services.threat_intel.threat_intel_service import ThreatIntelAggregator
from app.services.sandbox.attachment_sandbox import AttachmentSandboxEngine
from app.services.investigation.orchestrator import InvestigationOrchestrator


def _seed_intel_analysis(db_session, analysis_id="ANL-INTEL-001") -> EmailAnalysisModel:
    analysis = EmailAnalysisModel(
        analysis_id=analysis_id,
        filename="urgent_invoice_emotet.eml",
        sha256="44556677889900aabbccddeeff0011223344556677889900aabbccddeeff0011",
        status="completed",
        threat_type="malware_delivery",
        risk_score=94,
        severity="critical",
        ai_confidence=0.98,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id=analysis_id,
        from_email="spoofed-exec@micr0soft-portal.xyz",
        from_display_name="CEO Office",
        reply_to="attacker@c2-drop.attacker-infrastructure.xyz",
        subject="URGENT: Executive Wire Instructions & Invoice",
        message_id="<msg-wire-intel-99@micr0soft-portal.xyz>",
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
            sha256="5566778899001122334455667788990011223344556677889900112233445566",
            is_double_extension=True,
            is_executable=True,
            is_suspicious=True,
            size_bytes=194560,
        ),
        EmailAttachmentModel(
            analysis_id=analysis_id,
            filename="Financial_Ledger_Macro.docm",
            sha256="6677889900112233445566778899001122334455667788990011223344556677",
            is_double_extension=False,
            is_executable=False,
            is_suspicious=True,
            size_bytes=84200,
        ),
    ]
    db_session.add(analysis)
    db_session.commit()
    return analysis


def test_threat_intel_aggregator_enrichment(db_session):
    aggregator = ThreatIntelAggregator(db_session)

    # 1. Malicious Lookalike Domain
    res_domain = aggregator.enrich_indicator("micr0soft-portal.xyz", "domain")
    assert res_domain.overall_verdict == "MALICIOUS"
    assert res_domain.overall_score >= 80
    assert len(res_domain.providers) >= 2
    vt_p = next(p for p in res_domain.providers if p.provider == "virustotal")
    assert "engines" in vt_p.detection_ratio

    # 2. Tor Exit Node IP
    res_ip = aggregator.enrich_indicator("185.220.101.99", "ip")
    assert res_ip.overall_verdict == "MALICIOUS"
    abuse_p = next(p for p in res_ip.providers if p.provider == "abuseipdb")
    assert abuse_p.abuse_confidence is not None
    assert abuse_p.abuse_confidence > 70

    # 3. Clean Domain
    res_clean = aggregator.enrich_indicator("google.com", "domain")
    assert res_clean.overall_verdict == "CLEAN"
    assert res_clean.overall_score == 0


def test_threat_intel_24h_caching_and_expiration(db_session):
    aggregator = ThreatIntelAggregator(db_session)
    indicator = "c2-beacon-test.xyz"

    # First call: fresh query
    res1 = aggregator.enrich_indicator(indicator, "domain", force_refresh=False)
    assert res1.cached is False

    # Second call: cache hit
    res2 = aggregator.enrich_indicator(indicator, "domain", force_refresh=False)
    assert res2.cached is True
    assert res2.overall_verdict == res1.overall_verdict

    # Third call with force_refresh=True: cache bypass
    res3 = aggregator.enrich_indicator(indicator, "domain", force_refresh=True)
    assert res3.cached is False


def test_attachment_sandbox_executable_detonation(db_session):
    engine = AttachmentSandboxEngine(db_session)
    report = engine.analyze_attachment(
        filename="Invoice_Payment.pdf.exe",
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        is_double_extension=True,
        is_executable=True,
    )

    assert report.verdict == "MALICIOUS"
    assert report.risk_score >= 90
    assert "Double Extension Deception" in report.structural_flags[0]
    assert len(report.process_tree) >= 1
    root_proc = report.process_tree[0]
    assert root_proc.process_name == "explorer.exe"
    assert len(root_proc.children) >= 1

    # Check network callbacks & registry persistence
    assert len(report.network_callbacks) >= 1
    assert any(c.is_threat for c in report.network_callbacks)
    assert len(report.registry_modifications) >= 1
    assert any(r.is_persistence for r in report.registry_modifications)


def test_attachment_sandbox_macro_doc_analysis(db_session):
    engine = AttachmentSandboxEngine(db_session)
    report = engine.analyze_attachment(
        filename="Q4_Payroll.docm",
        sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    )

    assert report.verdict == "MALICIOUS"
    assert report.macro_analysis is not None
    assert report.macro_analysis["has_macros"] is True
    assert "AutoOpen" in report.macro_analysis["auto_exec"]
    assert len(report.mitre_techniques) >= 2


def test_attachment_sandbox_pdf_analysis(db_session):
    engine = AttachmentSandboxEngine(db_session)
    report = engine.analyze_attachment(
        filename="Statement.pdf",
        sha256="99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff",
    )

    assert report.verdict == "SUSPICIOUS"
    assert report.pdf_analysis is not None
    assert len(report.pdf_analysis["uri_actions"]) >= 1


def test_api_threat_intel_and_sandbox_endpoints(client, db_session):
    analysis_id = "ANL-INTEL-API-01"
    _seed_intel_analysis(db_session, analysis_id)

    # 1. POST /api/v1/investigations/{id}/enrich
    resp_enrich = client.post(f"/api/v1/investigations/{analysis_id}/enrich")
    assert resp_enrich.status_code == 200
    enrich_data = resp_enrich.json()
    assert enrich_data["total_indicators"] >= 3
    assert enrich_data["malicious_indicators_count"] >= 1
    assert len(enrich_data["attachments"]) == 2

    # 2. GET /api/v1/investigations/{id}/threat-intel
    resp_intel = client.get(f"/api/v1/investigations/{analysis_id}/threat-intel")
    assert resp_intel.status_code == 200
    intel_list = resp_intel.json()
    assert len(intel_list) >= 3
    assert any(i["overall_verdict"] == "MALICIOUS" for i in intel_list)

    # 3. GET /api/v1/investigations/{id}/attachments
    resp_att = client.get(f"/api/v1/investigations/{analysis_id}/attachments")
    assert resp_att.status_code == 200
    att_list = resp_att.json()
    assert len(att_list) == 2
    assert any(a["verdict"] == "MALICIOUS" for a in att_list)

    # 4. POST /api/v1/threat-intel/lookup
    resp_lookup = client.post(
        "/api/v1/threat-intel/lookup",
        json={"indicator": "micr0soft-portal.xyz", "indicator_type": "domain"},
    )
    assert resp_lookup.status_code == 200
    lookup_data = resp_lookup.json()
    assert lookup_data["overall_verdict"] == "MALICIOUS"
    assert len(lookup_data["providers"]) >= 2

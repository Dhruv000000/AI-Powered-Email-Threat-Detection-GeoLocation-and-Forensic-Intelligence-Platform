import pytest
from app.services.email_analysis.parser import EmailParser
from app.services.email_analysis.headers import HeaderAnalyzer

def test_analyze_relay_hops_and_auth(fixtures_dir):
    fixture_path = fixtures_dir / "phishing_credential_harvest.eml"
    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    parsed = EmailParser.parse_bytes(raw_bytes)
    hops = HeaderAnalyzer.analyze_relay_hops(parsed.headers)
    auth = HeaderAnalyzer.analyze_authentication(parsed.headers)

    assert len(hops) >= 1
    assert hops[0].ip == "185.220.101.54"
    assert hops[0].is_origin_node is True
    assert hops[0].is_private_ip is False

    assert auth.spf.status == "fail"
    assert auth.dkim.status == "fail"
    assert auth.dmarc.status == "fail"

def test_benign_auth_pass(fixtures_dir):
    fixture_path = fixtures_dir / "benign_executive.eml"
    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    parsed = EmailParser.parse_bytes(raw_bytes)
    auth = HeaderAnalyzer.analyze_authentication(parsed.headers)

    assert auth.spf.status == "pass"
    assert auth.dkim.status == "pass"
    assert auth.dmarc.status == "pass"

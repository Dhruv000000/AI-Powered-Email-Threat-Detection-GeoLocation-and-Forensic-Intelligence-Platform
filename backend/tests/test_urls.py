import pytest
from app.services.email_analysis.urls import UrlExtractor
from app.services.email_analysis.domains import DomainAnalyzer

def test_extract_urls_from_html():
    html = """
    <html>
        <body>
            <a href="http://185.220.101.54/login">Direct IP Login</a>
            <a href="http://login.micros0ft-verify.xyz/auth">Lookalike Domain</a>
            <a href="https://bit.ly/3xXyz99">Shortened Link</a>
        </body>
    </html>
    """
    urls = UrlExtractor.extract_urls("", html)
    assert len(urls) == 3

    ip_url = next(u for u in urls if u.is_ip_based)
    assert ip_url.hostname == "185.220.101.54"
    assert ip_url.threat_level in ("high", "critical")

    short_url = next(u for u in urls if u.is_shortened)
    assert short_url.is_shortened is True

def test_domain_lookalike_detection():
    is_spoof, desc = DomainAnalyzer.check_lookalike("micros0ft-login-verify.xyz")
    assert is_spoof is True
    assert "microsoft" in desc.lower()

    is_spoof_clean, _ = DomainAnalyzer.check_lookalike("enterprise-solutions.com")
    assert is_spoof_clean is False

def test_sender_domain_mismatch():
    mismatches = DomainAnalyzer.analyze_sender_domains(
        from_email="robert.vance@vance-holdings.com",
        reply_to_email="executive-escrow@confidential-ma-acquisitions.xyz",
        return_path="exec-relay@bulletproof-hosting.xyz"
    )
    codes = [m["code"] for m in mismatches]
    assert "REPLY_TO_MISMATCH" in codes
    assert "RETURN_PATH_MISMATCH" in codes

import pytest
from app.services.email_analysis.parser import EmailParser

def test_parse_benign_email(fixtures_dir):
    fixture_path = fixtures_dir / "benign_executive.eml"
    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    parsed = EmailParser.parse_bytes(raw_bytes)
    assert parsed.metadata["from_email"] == "sarah.jenkins@enterprise-solutions.com"
    assert parsed.metadata["from_domain"] == "enterprise-solutions.com"
    assert "dhruv.sharma@cyberdefense.gov.in" in parsed.metadata["to"]
    assert "Q3 Threat Intel Briefing Schedule" in parsed.metadata["subject"]
    assert len(parsed.headers) > 5
    assert "Attached is the agenda" in parsed.body_plain

def test_parse_multipart_email_with_attachment(fixtures_dir):
    fixture_path = fixtures_dir / "invoice_trojan_attachment.eml"
    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    parsed = EmailParser.parse_bytes(raw_bytes)
    assert len(parsed.attachments_raw) == 1
    att = parsed.attachments_raw[0]
    assert att["filename"] == "Overdue_Invoice_Statement_2026.pdf.vbs"
    assert att["content_type"] == "application/x-msdownload"
    assert len(att["payload_bytes"]) > 0

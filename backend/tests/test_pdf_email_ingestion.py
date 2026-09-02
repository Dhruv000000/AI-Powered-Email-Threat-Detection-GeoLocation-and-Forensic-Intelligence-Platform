import io
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.services.email_analysis.parser import EmailParser, ParsedEmailData
from app.services.email_analysis.orchestrator import AnalysisOrchestrator


def _generate_test_email_pdf() -> bytes:
    """Generates an RFC-formatted email message exported as a PDF document."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica", 10)

    lines = [
        "From: Executive Security <security@micr0soft-portal.xyz>",
        "To: employee@victim-corp.com",
        "Subject: URGENT: Wire Transfer Authorization & Credential Verification",
        "Date: Tue, 01 Sep 2026 14:30:00 +0000",
        "Reply-To: attacker@micr0soft-portal.xyz",
        "Message-ID: <pdf-msg-9921@micr0soft-portal.xyz>",
        "Received: from relay-eu-central.fin-proxy.de (185.220.101.5) by mail.victim-corp.com",
        "",
        "Dear Employee,",
        "",
        "Please immediately verify your corporate credentials and authorize wire payment:",
        "https://micr0soft-portal.xyz/login/verify-transfer",
        "",
        "Originating Gateway: 185.220.101.99",
        "Thank you, Corporate IT Security",
    ]

    y = 750
    for line in lines:
        c.drawString(50, y, line)
        y -= 18

    # Add hyperlink annotation to the canvas
    c.linkURL("https://micr0soft-portal.xyz/login/verify-transfer", (50, y - 20, 300, y))

    c.save()
    buffer.seek(0)
    return buffer.getvalue()


def test_pdf_email_parser_rfc_extraction():
    pdf_bytes = _generate_test_email_pdf()
    parsed: ParsedEmailData = EmailParser.parse_bytes(pdf_bytes, filename="urgent_security_alert.pdf")

    assert parsed is not None
    assert parsed.metadata["from_email"] == "security@micr0soft-portal.xyz"
    assert parsed.metadata["from_domain"] == "micr0soft-portal.xyz"
    assert parsed.metadata["from_display_name"] == "Executive Security"
    assert "victim-corp.com" in parsed.metadata["to"][0]
    assert "Wire Transfer Authorization" in parsed.metadata["subject"]
    assert "https://micr0soft-portal.xyz/login/verify-transfer" in parsed.body_plain
    assert any("relay-eu-central" in h[1] for h in parsed.headers if h[0] == "Received")


def test_pdf_email_full_orchestrator_pipeline(db_session):
    pdf_bytes = _generate_test_email_pdf()
    orchestrator = AnalysisOrchestrator(db_session)

    res = orchestrator.process_email(
        raw_bytes=pdf_bytes,
        filename="urgent_security_alert.pdf",
        force_reanalysis=True,
    )

    assert res.analysis_id.startswith("ANL-")
    assert res.status == "completed"
    assert res.classification.risk_score >= 60

    # Ensure extracted URLs and IPs are present in indicators
    urls = res.indicators.get("urls", [])
    ips = res.indicators.get("ips", [])
    assert any("micr0soft-portal.xyz" in u.original_url for u in urls)
    assert any("185.220.101" in ip.ip for ip in ips)


def test_pdf_email_upload_api(client):
    pdf_bytes = _generate_test_email_pdf()

    response = client.post(
        "/api/v1/email-analysis/analyze",
        files={"file": ("urgent_security_alert.pdf", pdf_bytes, "application/pdf")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"].startswith("ANL-")
    assert data["status"] == "completed"
    assert data["classification"]["risk_score"] >= 60
    assert len(data["indicators"]["urls"]) >= 1

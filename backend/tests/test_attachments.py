import pytest
import hashlib
from app.services.email_analysis.attachments import AttachmentAnalyzer

def test_attachment_hashing_and_double_extension():
    mock_payload = b"test malicious vbs script payload"
    expected_sha256 = hashlib.sha256(mock_payload).hexdigest()

    raw_attachments = [
        {
            "filename": "Quarterly_Invoice_2026.pdf.vbs",
            "content_type": "application/x-msdownload",
            "payload_bytes": mock_payload,
        }
    ]

    results, assessment = AttachmentAnalyzer.analyze_attachments(raw_attachments)
    assert len(results) == 1
    att = results[0]
    assert att.sha256 == expected_sha256
    assert att.is_double_extension is True
    assert att.is_executable is True
    assert att.is_suspicious is True
    assert assessment == "suspicious"

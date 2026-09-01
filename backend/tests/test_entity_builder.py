import pytest
from app.services.investigation.entity_builder import EntityBuilder
from app.db.models.email_analysis import (
    EmailAnalysisModel,
    EmailMetadataModel,
    EmailUrlModel,
    EmailIpModel,
    EmailAttachmentModel,
    EmailRelayHopModel,
)
from app.schemas.email_analysis import (
    EmailAnalysisResponse,
    EmailMetadataSchema,
    ExtractedUrlSchema,
    ExtractedIpSchema,
    AttachmentMetadataSchema,
    RelayHopSchema,
    AuthenticationResultsSchema,
    AuthStatusItem,
    ClassificationResultSchema,
    ProbableOriginSchema,
    EvidenceMetadataSchema,
)


def test_email_address_normalization():
    # Case insensitivity & angle bracket parsing
    norm1, dom1, name1 = EntityBuilder.normalize_email_address("User@Example.COM")
    norm2, dom2, name2 = EntityBuilder.normalize_email_address("user@example.com")
    norm3, dom3, name3 = EntityBuilder.normalize_email_address('"John Doe" <USER@EXAMPLE.COM>')

    assert norm1 == "user@example.com"
    assert norm2 == "user@example.com"
    assert norm3 == "user@example.com"
    assert dom1 == "example.com"
    assert dom2 == "example.com"
    assert dom3 == "example.com"
    assert name3 == "John Doe"


def test_domain_normalization():
    dom1 = EntityBuilder.normalize_domain("Example.COM.")
    dom2 = EntityBuilder.normalize_domain("example.com:8080")
    dom3 = EntityBuilder.normalize_domain("  SUB.EXAMPLE.COM  ")

    assert dom1 == "example.com"
    assert dom2 == "example.com"
    assert dom3 == "sub.example.com"


def test_url_normalization_static():
    url_hash1, norm1, scheme1, host1, dom1 = EntityBuilder.normalize_url("HTTPS://Secure-Login.XYZ:443/auth/login?session=123")
    url_hash2, norm2, scheme2, host2, dom2 = EntityBuilder.normalize_url("https://secure-login.xyz/auth/login?session=123")

    assert norm1 == "https://secure-login.xyz/auth/login?session=123"
    assert norm2 == "https://secure-login.xyz/auth/login?session=123"
    assert url_hash1 == url_hash2
    assert scheme1 == "https"
    assert host1 == "secure-login.xyz"
    assert dom1 == "secure-login.xyz"


def test_ip_normalization():
    ip1, ver1, priv1 = EntityBuilder.normalize_ip("192.168.1.1")
    ip2, ver2, priv2 = EntityBuilder.normalize_ip("185.220.101.5")
    ip3, ver3, priv3 = EntityBuilder.normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    assert ip1 == "192.168.1.1"
    assert priv1 is True
    assert ip2 == "185.220.101.5"
    assert priv2 is False
    assert ver3 == 6


def test_entity_builder_extraction_from_model():
    analysis = EmailAnalysisModel(
        analysis_id="ANL-TEST-001",
        filename="phishing.eml",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="completed",
        threat_type="phishing",
        risk_score=85,
        severity="high",
        ai_confidence=0.91,
    )
    analysis.metadata_record = EmailMetadataModel(
        analysis_id="ANL-TEST-001",
        from_header='"Security Alert" <alert@paypal-security.xyz>',
        from_email="alert@paypal-security.xyz",
        from_domain="paypal-security.xyz",
        reply_to="stealth-attacker@darkmail.xyz",
        to_recipients=["victim@enterprise.com"],
        subject="Action Required: Account Suspended",
        date_header="Fri, 29 Aug 2026 10:00:00 +0000",
    )
    analysis.urls = [
        EmailUrlModel(
            analysis_id="ANL-TEST-001",
            original_url="https://paypal-security.xyz/verify",
            normalized_url="https://paypal-security.xyz/verify",
            scheme="https",
            domain="paypal-security.xyz",
            is_lookalike=True,
            risk_score=90,
            threat_level="high",
        )
    ]
    analysis.attachments = [
        EmailAttachmentModel(
            analysis_id="ANL-TEST-001",
            filename="invoice.pdf.exe",
            sha256="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            is_executable=True,
            is_suspicious=True,
        )
    ]
    analysis.relay_hops = [
        EmailRelayHopModel(
            analysis_id="ANL-TEST-001",
            hop_number=1,
            from_server="mail.origin-server.xyz",
            ip="185.220.101.44",
            is_origin_node=True,
        )
    ]

    builder = EntityBuilder(analysis, investigation_id="INV-TEST-001")
    entities = builder.build_all_entities()

    entity_types = {e["type"] for e in entities}
    assert "Email" in entity_types
    assert "EmailAddress" in entity_types
    assert "Domain" in entity_types
    assert "URL" in entity_types
    assert "Attachment" in entity_types
    assert "FileHash" in entity_types
    assert any(e["type"] in ("IP", "IPAddress") for e in entities)
    assert "MailServer" in entity_types

    # Ensure deterministic IDs
    email_node = next(e for e in entities if e["type"] == "Email")
    assert email_node["id"] == "email:ANL-TEST-001"
    assert email_node["properties"]["threat_type"] == "phishing"
    assert email_node["properties"]["risk_score"] == 85

    # Check Domain properties
    domain_node = next(e for e in entities if e["type"] == "Domain" and e["display_label"] == "paypal-security.xyz")
    assert domain_node["properties"]["domain_name"] == "paypal-security.xyz"
    assert domain_node["properties"]["tld"] == "xyz"


def test_entity_builder_extraction_from_pydantic_dto():
    dto = EmailAnalysisResponse(
        analysis_id="ANL-DTO-001",
        status="completed",
        email=EmailMetadataSchema(
            subject="Urgent: Invoice Overdue",
            from_header="Finance <finance@evil-corp.com>",
            from_email="finance@evil-corp.com",
            reply_to="hacker@fraud.net",
            to_recipients=["victim@target.org"],
            date_header="Mon, 01 Sep 2026 08:00:00 +0000",
        ),
        classification=ClassificationResultSchema(
            threat_type="phishing",
            risk_score=92,
            severity="critical",
            ai_confidence=0.96,
        ),
        authentication=AuthenticationResultsSchema(
            spf=AuthStatusItem(status="fail"),
            dkim=AuthStatusItem(status="none"),
            dmarc=AuthStatusItem(status="fail"),
        ),
        relay_path=[
            RelayHopSchema(
                hop_number=1,
                by_server="mx.target.org",
                ip="203.0.113.10",
                is_origin_node=True,
                raw_header="Received: from mail.evil-corp.com by mx.target.org with ESMTP",
            )
        ],
        indicators={
            "urls": [
                {
                    "original_url": "https://evil-corp.com/login",
                    "normalized_url": "https://evil-corp.com/login",
                    "scheme": "https",
                    "hostname": "evil-corp.com",
                    "domain": "evil-corp.com",
                    "risk_score": 95,
                    "threat_level": "critical",
                    "is_lookalike": True,
                }
            ],
            "ips": [
                {
                    "ip": "198.51.100.99",
                    "source": "url_host",
                    "is_probable_origin": False,
                }
            ],
            "attachments": [
                {
                    "filename": "payload.exe",
                    "sha256": "c0ffee1234567890",
                    "content_type": "application/x-dosexec",
                    "size_bytes": 4096,
                    "is_executable": True,
                    "is_suspicious": True,
                }
            ],
        },
        probable_origin=ProbableOriginSchema(ip="203.0.113.10", confidence=0.88),
        evidence=EvidenceMetadataSchema(
            sha256="deadbeef12345678",
            filename="threat_sample.eml",
            file_size_bytes=1024,
        ),
    )

    builder = EntityBuilder(dto, investigation_id="INV-DTO-001")
    entities = builder.build_all_entities()

    email_node = next(e for e in entities if e["type"] == "Email")
    assert email_node["id"] == "email:ANL-DTO-001"
    assert email_node["properties"]["threat_type"] == "phishing"
    assert email_node["properties"]["risk_score"] == 92

    url_node = next(e for e in entities if e["type"] == "URL")
    assert url_node["properties"]["is_lookalike"] is True
    assert url_node["properties"]["hostname"] == "evil-corp.com"

    att_node = next(e for e in entities if e["type"] == "Attachment")
    assert att_node["properties"]["filename"] == "payload.exe"
    assert att_node["properties"]["is_executable"] is True

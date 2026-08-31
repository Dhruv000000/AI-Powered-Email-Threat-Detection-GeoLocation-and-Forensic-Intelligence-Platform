import pytest
from app.services.email_analysis.features import FeatureExtractor
from app.schemas.email_analysis import (
    AuthenticationResultsSchema,
    AuthStatusItem,
    RelayHopSchema,
    ExtractedUrlSchema,
    ExtractedIpSchema,
    AttachmentMetadataSchema,
)

def test_feature_extraction_vector():
    auth = AuthenticationResultsSchema(
        spf=AuthStatusItem(status="fail"),
        dkim=AuthStatusItem(status="fail"),
        dmarc=AuthStatusItem(status="fail"),
    )
    relay_hops = [
        RelayHopSchema(hop_number=1, ip="185.220.101.54", raw_header="from mail by server"),
        RelayHopSchema(hop_number=2, ip="10.0.0.1", raw_header="from relay by mx"),
    ]
    urls = [
        ExtractedUrlSchema(
            original_url="http://185.220.101.54/login",
            normalized_url="http://185.220.101.54/login",
            scheme="http",
            is_ip_based=True,
            threat_level="critical",
        )
    ]
    ips = [
        ExtractedIpSchema(ip="185.220.101.54", is_private=False)
    ]
    attachments = []
    linguistics = {
        "urgency_score": 0.8,
        "credential_request_score": 0.9,
        "financial_request_score": 0.0,
        "impersonation_score": 0.6,
    }
    sender_anomalies = [{"code": "REPLY_TO_MISMATCH", "severity": "high"}]

    features = FeatureExtractor.extract_features(
        metadata={"from_email": "test@domain.com"},
        auth=auth,
        relay_hops=relay_hops,
        urls=urls,
        ips=ips,
        attachments=attachments,
        linguistics=linguistics,
        sender_anomalies=sender_anomalies,
        domain_lookalikes=["micros0ft"],
        suspicious_tld_count=1,
    )

    assert features["spf_failed"] == 1.0
    assert features["dkim_failed"] == 1.0
    assert features["reply_to_mismatch"] == 1.0
    assert features["ip_url_count"] == 1.0
    assert features["urgency_score"] == 0.8
    assert features["credential_request_score"] == 0.9
    assert features["lookalike_domain_count"] == 1.0

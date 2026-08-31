import pytest
from app.services.email_analysis.risk_scoring import RiskScoringEngine

def test_risk_scoring_phishing_high():
    features = {
        "spf_failed": 1.0,
        "dkim_failed": 1.0,
        "dmarc_failed": 1.0,
        "ip_url_count": 1.0,
        "lookalike_domain_count": 1.0,
        "credential_request_score": 0.8,
        "urgency_score": 0.7,
    }
    score, severity, components = RiskScoringEngine.calculate_risk(
        predicted_threat_type="phishing",
        ai_confidence=0.94,
        features=features,
    )

    assert score >= 55
    assert severity in ("medium", "high", "critical")
    assert "authentication" in components
    assert "linguistic" in components

def test_risk_scoring_benign_low():
    features = {
        "spf_failed": 0.0,
        "dkim_failed": 0.0,
        "dmarc_failed": 0.0,
        "reply_to_mismatch": 0.0,
        "url_count": 1.0,
        "suspicious_url_count": 0.0,
        "urgency_score": 0.0,
    }
    score, severity, components = RiskScoringEngine.calculate_risk(
        predicted_threat_type="benign",
        ai_confidence=0.98,
        features=features,
    )

    assert score < 20
    assert severity == "low"
    assert components["final_score"] == score

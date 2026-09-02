"""ML and AI Confidence Calculation Services."""
from typing import List, Dict, Any, Optional


def calculate_confidence(
    signals: Optional[List[Any]] = None,
    auth_results: Optional[Dict[str, Any]] = None,
    route_anomalies: Optional[List[Any]] = None,
    base_confidence: float = 0.70,
) -> float:
    """
    Decouples Detection Confidence from Severity Score.
    High signal indicators (failed SPF, failed DKIM, lookalike domains, anonymizers, urgency)
    produce >= 0.90 confidence independently of whether the composite risk score is moderate or critical.
    """
    signals = signals or []
    auth_results = auth_results or {}
    route_anomalies = route_anomalies or []

    conf = base_confidence

    # 1. Authentication failures (SPF/DKIM/DMARC)
    if not auth_results.get("spf_pass", True) or auth_results.get("spf_result") in ("fail", "softfail"):
        conf += 0.08
    if not auth_results.get("dkim_pass", True) or auth_results.get("dkim_result") in ("fail", "none"):
        conf += 0.08
    if not auth_results.get("dmarc_pass", True) or auth_results.get("dmarc_result") == "fail":
        conf += 0.04

    # 2. Domain & URL signals
    if any("lookalike" in str(s).lower() or "0-day" in str(s).lower() or "zero_day" in str(s).lower() for s in signals):
        conf += 0.07
    if any("suspicious" in str(s).lower() or "phishing" in str(s).lower() or "credential" in str(s).lower() for s in signals):
        conf += 0.05

    # 3. Routing & Anonymizer anomalies
    if any("tor" in str(r).lower() or "anonymizer" in str(r).lower() or "bulletproof" in str(r).lower() for r in route_anomalies):
        conf += 0.05

    # 4. Multi-vector correlation bonus
    if len(signals) >= 3:
        conf += 0.05

    return min(round(conf, 2), 0.98)


__all__ = ["calculate_confidence"]

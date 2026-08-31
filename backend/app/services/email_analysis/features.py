import json
import hashlib
from typing import Dict, Any, List
from app.schemas.email_analysis import (
    AuthenticationResultsSchema,
    RelayHopSchema,
    ExtractedUrlSchema,
    ExtractedIpSchema,
    AttachmentMetadataSchema,
)

class FeatureExtractor:
    """Forensic feature extraction service generating structured, versioned, hashable feature vectors."""

    FEATURE_SCHEMA_VERSION = "1.0"
    RULE_ENGINE_VERSION = "1.0"

    @classmethod
    def extract_features(
        cls,
        metadata: Dict[str, Any],
        auth: AuthenticationResultsSchema,
        relay_hops: List[RelayHopSchema],
        urls: List[ExtractedUrlSchema],
        ips: List[ExtractedIpSchema],
        attachments: List[AttachmentMetadataSchema],
        linguistics: Dict[str, Any],
        sender_anomalies: List[Dict[str, Any]],
        domain_lookalikes: List[str],
        suspicious_tld_count: int,
    ) -> Dict[str, float]:
        features: Dict[str, float] = {}

        # 1. Authentication Features
        features["spf_failed"] = 1.0 if auth.spf.status in ("fail", "softfail", "permerror") else 0.0
        features["dkim_failed"] = 1.0 if auth.dkim.status in ("fail", "permerror") else 0.0
        features["dmarc_failed"] = 1.0 if auth.dmarc.status in ("fail", "none") and auth.spf.status in ("fail", "softfail") else 0.0
        features["authentication_missing"] = 1.0 if auth.spf.status == "unknown" and auth.dkim.status == "unknown" else 0.0

        # 2. Sender Anomalies
        has_reply_to_mismatch = any(a["code"] == "REPLY_TO_MISMATCH" for a in sender_anomalies)
        has_return_path_mismatch = any(a["code"] == "RETURN_PATH_MISMATCH" for a in sender_anomalies)
        features["reply_to_mismatch"] = 1.0 if has_reply_to_mismatch else 0.0
        features["return_path_mismatch"] = 1.0 if has_return_path_mismatch else 0.0
        features["sender_domain_mismatch"] = 1.0 if (has_reply_to_mismatch or has_return_path_mismatch) else 0.0
        
        disp_name = str(metadata.get("from_display_name") or "").lower()
        if any(kw in disp_name for kw in ("ceo", "cfo", "president", "executive", "director", "security team", "microsoft", "it support")):
            features["display_name_impersonation_signal"] = max(float(linguistics.get("impersonation_score", 0.0)), 0.7)
        else:
            features["display_name_impersonation_signal"] = float(linguistics.get("impersonation_score", 0.0))

        # 3. URL Indicators
        features["url_count"] = float(len(urls))
        features["suspicious_url_count"] = float(sum(1 for u in urls if u.threat_level in ("high", "critical", "suspicious")))
        features["ip_url_count"] = float(sum(1 for u in urls if u.is_ip_based))
        features["shortened_url_count"] = float(sum(1 for u in urls if u.is_shortened))
        features["punycode_url_count"] = float(sum(1 for u in urls if u.is_punycode or u.is_lookalike))

        # 4. Domain Indicators
        features["domain_count"] = float(len(set(u.domain for u in urls if u.domain)))
        features["lookalike_domain_count"] = float(len(domain_lookalikes))
        features["suspicious_tld_count"] = float(suspicious_tld_count)
        domain_anomaly = 0.0
        if len(domain_lookalikes) > 0:
            domain_anomaly += 0.6
        if suspicious_tld_count > 0:
            domain_anomaly += 0.4
        features["domain_anomaly_score"] = min(domain_anomaly, 1.0)

        # 5. Attachment Indicators
        features["attachment_count"] = float(len(attachments))
        features["suspicious_attachment_count"] = float(sum(1 for a in attachments if a.is_suspicious))
        features["executable_attachment_signal"] = float(sum(1 for a in attachments if a.is_executable or a.is_double_extension))

        # 6. Linguistic Intent Signals
        features["urgency_score"] = float(linguistics.get("urgency_score", 0.0))
        features["credential_request_score"] = float(linguistics.get("credential_request_score", 0.0))
        features["financial_request_score"] = float(linguistics.get("financial_request_score", 0.0))
        features["impersonation_score"] = float(linguistics.get("impersonation_score", 0.0))

        # 7. Relay & Header Anomalies
        features["received_hop_count"] = float(len(relay_hops))
        header_anomalies = sum(1 for h in relay_hops if h.is_anomaly)
        features["header_anomaly_score"] = min(header_anomalies * 0.5, 1.0)

        return {k: round(float(v), 4) for k, v in features.items()}

    @classmethod
    def compute_feature_hash(cls, features: Dict[str, float]) -> str:
        """
        Generate deterministic SHA-256 hash of the normalized, sorted feature vector.
        Guarantees: Same features -> Same hash; Different features -> Different hash.
        """
        sorted_items = sorted(features.items())
        serialized = json.dumps(dict(sorted_items), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

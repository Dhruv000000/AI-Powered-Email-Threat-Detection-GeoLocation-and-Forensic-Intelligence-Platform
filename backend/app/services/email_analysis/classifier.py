import os
import joblib
import numpy as np
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional
from app.core.config import settings
from app.core.logging import logger

class ThreatClassifier(ABC):
    """Abstract classifier interface for threat classification."""

    @abstractmethod
    def predict(self, feature_dict: Dict[str, float]) -> Tuple[str, Optional[float], Dict[str, float], bool]:
        """
        Return tuple of:
        (predicted_threat_type, model_confidence, feature_contributions, ml_available)
        """
        pass


class SklearnThreatClassifier(ThreatClassifier):
    """Scikit-learn classification implementation with calibrated probabilities and graceful fallback."""

    CLASSES = [
        "benign",
        "phishing",
        "business_email_compromise",
        "malicious_attachment",
        "spam",
        "suspicious"
    ]

    MODEL_NAME = "aegis_email_classifier"
    MODEL_VERSION = "1.0.0"
    MODEL_TYPE = "synthetic-data baseline"

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.pipeline = None
        self.ml_available = False
        self._load_model()

    def _load_model(self):
        if self.model_path and os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                self.ml_available = True
                logger.info(f"Loaded calibrated Scikit-learn threat model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Could not load ML artifact from {self.model_path}: {e}. Operating in deterministic fallback mode.")
                self.pipeline = None
                self.ml_available = False
        else:
            logger.info(f"No ML artifact found at {self.model_path}. Operating in deterministic fallback mode.")
            self.pipeline = None
            self.ml_available = False

    def predict(self, feature_dict: Dict[str, float]) -> Tuple[str, Optional[float], Dict[str, float], bool]:
        if self.pipeline and self.ml_available:
            try:
                # Format feature vector strictly ordered by sorted key name
                feature_keys = sorted(feature_dict.keys())
                vec = np.array([[feature_dict[k] for k in feature_keys]])
                probas = self.pipeline.predict_proba(vec)[0]
                best_idx = int(np.argmax(probas))
                pred_class = str(self.pipeline.classes_[best_idx])
                confidence = float(probas[best_idx])
                
                # Active feature contributions for explainability
                contributions = {k: round(v * 10.0, 2) for k, v in feature_dict.items() if v > 0}
                return pred_class, round(confidence, 4), contributions, True
            except Exception as e:
                logger.error(f"Inference error in Scikit-learn pipeline: {e}. Falling back to deterministic rules.")

        # --- Deterministic DFIR Rule Fallback (When ML is unavailable) ---
        pred_class, rule_conf, contribs = self._development_predict(feature_dict)
        return pred_class, rule_conf, contribs, False

    def _development_predict(self, f: Dict[str, float]) -> Tuple[str, float, Dict[str, float]]:
        """Deterministic forensic rule evaluation when ML model is unavailable."""
        spf_fail = f.get("spf_failed", 0.0)
        dkim_fail = f.get("dkim_failed", 0.0)
        reply_to_mismatch = f.get("reply_to_mismatch", 0.0)
        return_path_mismatch = f.get("return_path_mismatch", 0.0)
        suspicious_urls = f.get("suspicious_url_count", 0.0)
        ip_urls = f.get("ip_url_count", 0.0)
        lookalike_domains = f.get("lookalike_domain_count", 0.0)
        suspicious_attachments = f.get("suspicious_attachment_count", 0.0)
        executable_attachments = f.get("executable_attachment_signal", 0.0)
        urgency = f.get("urgency_score", 0.0)
        credential = f.get("credential_request_score", 0.0)
        financial = f.get("financial_request_score", 0.0)
        impersonation = f.get("impersonation_score", 0.0)

        # 1. Check Malicious Attachment Signal
        if executable_attachments > 0 or suspicious_attachments > 0:
            confidence = 0.94 if executable_attachments > 0 else 0.84
            return "malicious_attachment", confidence, {
                "executable_attachment_signal": 45.0,
                "suspicious_attachment_count": 35.0,
                "urgency_score": urgency * 20.0
            }

        # 2. Check BEC (Financial transfer request + Executive impersonation / Urgency / Reply-To mismatch)
        if financial > 0.2 and (impersonation > 0.2 or urgency > 0.2 or reply_to_mismatch > 0):
            confidence = 0.93 if (financial > 0.3 and impersonation > 0.3) else 0.85
            return "business_email_compromise", confidence, {
                "financial_request_score": financial * 35.0,
                "impersonation_score": impersonation * 25.0,
                "urgency_score": urgency * 20.0,
                "reply_to_mismatch": reply_to_mismatch * 20.0
            }

        # 3. Check Phishing (Credential harvest + Lookalike domain / Suspicious URL / Auth Failure / Urgency)
        if credential > 0.2 or lookalike_domains > 0 or suspicious_urls > 0 or ip_urls > 0:
            confidence = 0.92 if (credential > 0.3 or lookalike_domains > 0) else 0.82
            return "phishing", confidence, {
                "credential_request_score": credential * 35.0,
                "lookalike_domain_count": lookalike_domains * 30.0,
                "suspicious_url_count": suspicious_urls * 25.0,
                "urgency_score": urgency * 10.0
            }

        # 4. Check Suspicious (Anomalies present but lower confidence)
        if spf_fail > 0 or dkim_fail > 0 or urgency > 0.4:
            return "suspicious", 0.72, {
                "spf_failed": spf_fail * 30.0,
                "urgency_score": urgency * 40.0,
            }

        # 5. Benign / Clean
        return "benign", 0.98, {"clean_baseline": 95.0}


class TransformerThreatClassifier(ThreatClassifier):
    """Slated for future LLM / Transformer release phases."""

    def __init__(self, model_name: str = "microsoft/deberta-v3-base"):
        self.model_name = model_name

    def predict(self, feature_dict: Dict[str, float]) -> Tuple[str, Optional[float], Dict[str, float], bool]:
        raise NotImplementedError("TransformerThreatClassifier is slated for future release phases.")

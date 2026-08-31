from typing import Dict, Any, Tuple, List, Optional
from app.core.config import settings

class RiskScoringEngine:
    """
    Normalized, evidence-first forensic risk scoring engine.
    
    Mathematical Model:
    1. Every forensic dimension is calculated from extracted evidence and normalized to [0.0, 1.0].
    2. Dimensions are weighted using configurable weights that sum to exactly 1.0.
    3. The forensic base score is scaled to [0, 100].
    4. Calibrated ML probability contributes a bounded adjustment (±15 max) without dominating evidence.
    5. The final score is clamped to [0, 100].
    
    IMPORTANT: Threat classification never directly overrides or hardcodes the risk score.
    """

    FORENSIC_WEIGHTS: Dict[str, float] = {
        "authentication": 0.15,
        "sender": 0.20,
        "url_domain": 0.25,
        "attachment": 0.20,
        "linguistic": 0.20,
    }

    # Maximum raw capacity per dimension
    DIMENSION_MAXIMA: Dict[str, float] = {
        "authentication": 25.0,
        "sender": 30.0,
        "url_domain": 35.0,
        "attachment": 40.0,
        "linguistic": 30.0,
    }

    @classmethod
    def calculate_risk(
        cls,
        predicted_threat_type: str,
        ai_confidence: Optional[float],
        features: Dict[str, float],
        ml_available: bool = True,
    ) -> Tuple[int, str, Dict[str, Any]]:
        # ----------------------------------------------------------------------
        # 1. Authentication Evidence Dimension (Max Raw: 25)
        # ----------------------------------------------------------------------
        auth_signals: List[str] = []
        auth_raw = 0.0
        if features.get("spf_failed", 0.0) > 0:
            auth_raw += 15.0
            auth_signals.append("SPF verification failed")
        if features.get("dkim_failed", 0.0) > 0:
            auth_raw += 15.0
            auth_signals.append("DKIM cryptographic signature invalid")
        if features.get("dmarc_failed", 0.0) > 0:
            auth_raw += 15.0
            auth_signals.append("DMARC domain alignment policy failed")
        
        norm_auth = min(1.0, auth_raw / cls.DIMENSION_MAXIMA["authentication"])

        # ----------------------------------------------------------------------
        # 2. Sender Inconsistency Evidence Dimension (Max Raw: 30)
        # ----------------------------------------------------------------------
        sender_signals: List[str] = []
        sender_raw = 0.0
        if features.get("reply_to_mismatch", 0.0) > 0:
            sender_raw += 25.0
            sender_signals.append("Reply-To domain diverges from sender From domain")
        if features.get("return_path_mismatch", 0.0) > 0:
            sender_raw += 15.0
            sender_signals.append("Return-Path envelope domain mismatch")
        if features.get("display_name_impersonation_signal", 0.0) > 0.4:
            sender_raw += 15.0
            sender_signals.append("Display name exhibits brand or executive authority impersonation")
        
        norm_sender = min(1.0, sender_raw / cls.DIMENSION_MAXIMA["sender"])

        # ----------------------------------------------------------------------
        # 3. URL & Domain Threat Evidence Dimension (Max Raw: 35)
        # ----------------------------------------------------------------------
        url_signals: List[str] = []
        url_raw = 0.0
        lookalikes = features.get("lookalike_domain_count", 0.0)
        if lookalikes > 0:
            url_raw += 25.0
            url_signals.append(f"Lookalike / homoglyph brand impersonation domain observed ({int(lookalikes)})")
        if features.get("ip_url_count", 0.0) > 0:
            url_raw += 25.0
            url_signals.append("Direct IP URL destination without DNS domain resolution")
        susp_urls = features.get("suspicious_url_count", 0.0)
        if susp_urls > 0:
            url_raw += min(susp_urls * 20.0, 25.0)
            url_signals.append(f"High-risk / suspicious hyperlink detected ({int(susp_urls)})")
        if features.get("punycode_url_count", 0.0) > 0:
            url_raw += 15.0
            url_signals.append("Punycode / internationalized character encoding observed")
        if features.get("suspicious_tld_count", 0.0) > 0:
            url_raw += 15.0
            url_signals.append("Suspicious / abuse-prevalent Top-Level Domain observed")
        
        norm_url_domain = min(1.0, url_raw / cls.DIMENSION_MAXIMA["url_domain"])

        # ----------------------------------------------------------------------
        # 4. Attachment Threat Evidence Dimension (Max Raw: 40)
        # ----------------------------------------------------------------------
        att_signals: List[str] = []
        att_raw = 0.0
        exec_signal = features.get("executable_attachment_signal", 0.0)
        if exec_signal > 0:
            att_raw += 40.0
            att_signals.append("Deceptive double extension (.pdf.exe) or executable payload indicator")
        elif features.get("suspicious_attachment_count", 0.0) > 0:
            att_raw += 25.0
            att_signals.append("Suspicious / active script container attachment observed")
        
        norm_attachment = min(1.0, att_raw / cls.DIMENSION_MAXIMA["attachment"])

        # ----------------------------------------------------------------------
        # 5. Linguistic Intent Evidence Dimension (Max Raw: 30)
        # Grouped into distinct intent sub-dimensions to prevent keyword double counting
        # ----------------------------------------------------------------------
        ling_signals: List[str] = []
        ling_raw = 0.0
        cred = features.get("credential_request_score", 0.0)
        fin = features.get("financial_request_score", 0.0)
        imp = features.get("impersonation_score", 0.0)
        urgency = features.get("urgency_score", 0.0)

        if cred >= 0.2:
            ling_raw += min(cred * 25.0, 20.0)
            ling_signals.append("Credential verification / re-authentication solicitation")
        if fin >= 0.2:
            ling_raw += min(fin * 25.0, 20.0)
            ling_signals.append("Financial wire transfer / monetary remittance solicitation")
        if imp >= 0.2:
            ling_raw += min(imp * 15.0, 15.0)
            ling_signals.append("Executive authority / confidential meeting pressure cues")
        if urgency >= 0.2:
            ling_raw += min(urgency * 10.0, 10.0)
            ling_signals.append("Coercive deadline / artificial urgency tactics")
        
        norm_linguistic = min(1.0, ling_raw / cls.DIMENSION_MAXIMA["linguistic"])

        # ----------------------------------------------------------------------
        # 6. Weighted Forensic Score Calculation (0.0 to 100.0)
        # ----------------------------------------------------------------------
        w = cls.FORENSIC_WEIGHTS
        forensic_normalized = (
            (w["authentication"] * norm_auth) +
            (w["sender"] * norm_sender) +
            (w["url_domain"] * norm_url_domain) +
            (w["attachment"] * norm_attachment) +
            (w["linguistic"] * norm_linguistic)
        )
        forensic_score = forensic_normalized * 100.0

        # ----------------------------------------------------------------------
        # 7. Calibrated ML Signal Contribution (Bounded: ±15.0 max)
        # ----------------------------------------------------------------------
        ml_adjustment = 0.0
        conf = ai_confidence if (ai_confidence is not None and ml_available) else 0.0
        
        if ml_available and conf > 0:
            if predicted_threat_type in ("phishing", "business_email_compromise", "malicious_attachment", "suspicious", "spam"):
                # Proportional positive threat adjustment
                ml_adjustment = conf * 15.0
            elif predicted_threat_type == "benign":
                # Proportional negative baseline adjustment
                ml_adjustment = - (conf * 10.0)

        # ----------------------------------------------------------------------
        # 8. Final Clamped Risk Score [0 - 100] & Severity Assignment
        # ----------------------------------------------------------------------
        raw_combined = forensic_score + ml_adjustment
        final_score = max(0, min(100, int(round(raw_combined))))

        if final_score <= settings.RISK_LOW_MAX:
            severity = "low"
        elif final_score <= settings.RISK_MODERATE_MAX:
            severity = "moderate"
        elif final_score <= settings.RISK_MEDIUM_MAX:
            severity = "medium"
        elif final_score <= settings.RISK_HIGH_MAX:
            severity = "high"
        else:
            severity = "critical"

        # Structured diagnostic breakdown
        score_components = {
            "authentication": {
                "raw_score": round(auth_raw, 2),
                "max_possible": cls.DIMENSION_MAXIMA["authentication"],
                "normalized": round(norm_auth, 4),
                "weight": w["authentication"],
                "weighted_points": round(w["authentication"] * norm_auth * 100.0, 2),
                "signals": auth_signals,
            },
            "sender": {
                "raw_score": round(sender_raw, 2),
                "max_possible": cls.DIMENSION_MAXIMA["sender"],
                "normalized": round(norm_sender, 4),
                "weight": w["sender"],
                "weighted_points": round(w["sender"] * norm_sender * 100.0, 2),
                "signals": sender_signals,
            },
            "url_domain": {
                "raw_score": round(url_raw, 2),
                "max_possible": cls.DIMENSION_MAXIMA["url_domain"],
                "normalized": round(norm_url_domain, 4),
                "weight": w["url_domain"],
                "weighted_points": round(w["url_domain"] * norm_url_domain * 100.0, 2),
                "signals": url_signals,
            },
            "attachment": {
                "raw_score": round(att_raw, 2),
                "max_possible": cls.DIMENSION_MAXIMA["attachment"],
                "normalized": round(norm_attachment, 4),
                "weight": w["attachment"],
                "weighted_points": round(w["attachment"] * norm_attachment * 100.0, 2),
                "signals": att_signals,
            },
            "linguistic": {
                "raw_score": round(ling_raw, 2),
                "max_possible": cls.DIMENSION_MAXIMA["linguistic"],
                "normalized": round(norm_linguistic, 4),
                "weight": w["linguistic"],
                "weighted_points": round(w["linguistic"] * norm_linguistic * 100.0, 2),
                "signals": ling_signals,
            },
            "forensic_base_score": round(forensic_score, 2),
            "ml": {
                "available": ml_available,
                "model_confidence": ai_confidence if ml_available else None,
                "adjustment": round(ml_adjustment, 2),
            },
            "final_score": final_score,
            "weights_sum": round(sum(w.values()), 4),
        }

        return final_score, severity, score_components

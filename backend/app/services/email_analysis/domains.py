import re
from typing import List, Dict, Set, Any, Optional, Tuple
from app.schemas.email_analysis import ThreatIndicatorSchema

class DomainAnalyzer:
    """Forensic domain normalization and lookalike / sender mismatch analysis engine."""

    _SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "icu", "click", "buzz", "tk", "ml", "ga", "cf", "gq",
        "fit", "surf", "rest", "cam", "live", "space", "monster", "cfd", "sbs", "example"
    }

    _TARGETED_BRANDS = {
        "microsoft": ["micros0ft", "micr0soft", "microsft", "m1crosoft", "rnicrosoft", "micro-soft", "microsof"],
        "google": ["g00gle", "googel", "g0ogle", "googl-e", "goog1e"],
        "paypal": ["paypa1", "paypa-l", "pay-pal", "paypai", "paypall", "paypa"],
        "apple": ["app1e", "appl-e", "appie", "ap-ple"],
        "amazon": ["amaz0n", "amazn", "arnazon", "amaz-on"],
        "bankofamerica": ["bankofamer1ca", "bank-of-america", "bof-america", "bankofamerlca"],
        "chase": ["chase-security", "chase-update", "chase-bank-auth", "chas-e"],
        "docusign": ["d0cusign", "docus1gn", "docu-sign", "docuslgn"],
        "office365": ["office-365", "0ffice365", "office365-verify", "ms-office365"]
    }

    _LEGITIMATE_DOMAINS = {
        "microsoft.com", "google.com", "paypal.com", "apple.com", "amazon.com",
        "bankofamerica.com", "chase.com", "docusign.com", "office.com", "microsoftonline.com"
    }

    @classmethod
    def normalize_domain(cls, domain: str) -> str:
        if not domain:
            return ""
        dom = domain.lower().strip().rstrip(".")
        if dom.startswith("www."):
            dom = dom[4:]
        return dom

    @classmethod
    def is_suspicious_tld(cls, domain: str) -> bool:
        norm = cls.normalize_domain(domain)
        parts = norm.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            return tld in cls._SUSPICIOUS_TLDS
        return False

    @classmethod
    def check_lookalike(cls, domain: str) -> Tuple[bool, Optional[str]]:
        """Static lookalike pattern check against high-value spoofed target brands."""
        if not domain:
            return False, None

        norm = cls.normalize_domain(domain)
        if norm in cls._LEGITIMATE_DOMAINS:
            return False, None

        # Extract hostname body and tokens
        hostname_parts = norm.split(".")
        hostname_body = hostname_parts[0] if len(hostname_parts) > 1 else norm
        tokens = re.split(r"[-_.]+", norm)

        # 1. Direct dictionary match against known spoofed variations
        for brand, spoof_list in cls._TARGETED_BRANDS.items():
            for spoof in spoof_list:
                if spoof in norm or any(spoof == t for t in tokens):
                    return True, f"Lookalike variant impersonating '{brand}' (observed: '{spoof}')"

        # 2. Heuristic letter-digit substitution patterns on whole norm and each token
        substitutions = [("0", "o"), ("1", "l"), ("1", "i"), ("3", "e"), ("5", "s"), ("8", "b"), ("rn", "m"), ("vv", "w")]
        for brand, spoof_list in cls._TARGETED_BRANDS.items():
            brand_stem = brand.replace(" ", "").replace("-", "")

            # Check tokens and whole body
            candidates_to_check = [norm, hostname_body] + tokens
            for cand in candidates_to_check:
                if not cand:
                    continue
                de_obfuscated = cand
                for digit, char in substitutions:
                    de_obfuscated = de_obfuscated.replace(digit, char)

                if brand_stem in de_obfuscated:
                    # If candidate has digits or typos but de-obfuscates to brand
                    if any(c.isdigit() for c in cand) or ("rn" in cand) or ("vv" in cand) or (cand != brand_stem and brand_stem in cand):
                        return True, f"Homoglyph / alphanumeric substitution spoofing '{brand}' (observed token: '{cand}')"

        return False, None

    @classmethod
    def analyze_sender_domains(
        cls,
        from_email: Optional[str],
        reply_to_email: Optional[str],
        return_path: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Identify sender vs Reply-To and Return-Path anomalies."""
        signals = []

        from_domain = from_email.split("@")[-1].lower() if from_email and "@" in from_email else None
        reply_domain = reply_to_email.split("@")[-1].lower() if reply_to_email and "@" in reply_to_email else None
        return_domain = return_path.split("@")[-1].lower() if return_path and "@" in return_path else None

        # Check Reply-To Mismatch
        if from_domain and reply_domain and from_domain != reply_domain:
            signals.append({
                "code": "REPLY_TO_MISMATCH",
                "severity": "high",
                "title": "Reply-To Domain Mismatch",
                "description": f"The Reply-To address domain '{reply_domain}' diverges from the From sender domain '{from_domain}'. Replies will be routed to an external destination.",
                "from_domain": from_domain,
                "reply_to_domain": reply_domain,
            })

        # Check Return-Path Mismatch
        if from_domain and return_domain and from_domain != return_domain:
            signals.append({
                "code": "RETURN_PATH_MISMATCH",
                "severity": "medium",
                "title": "Return-Path Envelope Mismatch",
                "description": f"The envelope Return-Path domain '{return_domain}' differs from the From header domain '{from_domain}'.",
                "from_domain": from_domain,
                "return_path_domain": return_domain,
            })

        return signals

import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import List, Set, Dict, Any, Optional
from bs4 import BeautifulSoup
from app.schemas.email_analysis import ExtractedUrlSchema

class UrlExtractor:
    """Static URL and hyperlink extraction engine with security signal detection (Zero Network Egress)."""

    _URL_REGEX = re.compile(
        r'https?://[^\s<>"\'`]+',
        re.IGNORECASE
    )

    _SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "bit.do",
        "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy"
    }

    _SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "account", "secure", "update", "banking", "billing",
        "password", "credential", "auth", "sso", "mfa", "confirm", "wallet", "invoice"
    }

    @classmethod
    def extract_urls(cls, body_plain: str, body_html: str, headers: Optional[List] = None) -> List[ExtractedUrlSchema]:
        found_urls: Set[str] = set()

        # 1. Extract from plain text
        if body_plain:
            for match in cls._URL_REGEX.findall(body_plain):
                cleaned = match.rstrip(".,;:)>]'\"")
                if cleaned.startswith(("http://", "https://")):
                    found_urls.add(cleaned)

        # 2. Extract from HTML tags
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href.startswith(("http://", "https://")):
                        found_urls.add(href.rstrip(".,;:)>]'\""))
                for form in soup.find_all("form", action=True):
                    action = form["action"].strip()
                    if action.startswith(("http://", "https://")):
                        found_urls.add(action.rstrip(".,;:)>]'\""))
            except Exception:
                pass

            # Also check remaining raw HTML text
            for match in cls._URL_REGEX.findall(body_html):
                cleaned = match.split('"')[0].split("'")[0].split(">")[0].split("<")[0].rstrip(".,;:)>]'\"")
                if cleaned.startswith(("http://", "https://")):
                    found_urls.add(cleaned)

        results: List[ExtractedUrlSchema] = []
        
        for url in sorted(found_urls):
            parsed_item = cls._analyze_single_url(url)
            results.append(parsed_item)

        return results

    @classmethod
    def _analyze_single_url(cls, original_url: str) -> ExtractedUrlSchema:
        try:
            parsed = urlparse(original_url)
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
            path = parsed.path or "/"
            query = parsed.query or None
            
            # Normalization
            normalized = f"{scheme}://{hostname}"
            if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                normalized += f":{port}"
            normalized += path
            if query:
                normalized += f"?{query}"
        except Exception:
            scheme = "http"
            hostname = ""
            path = "/"
            query = None
            normalized = original_url

        # Check IP-based Host
        is_ip = False
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                is_ip = False

        # Extract root domain
        domain = hostname
        if hostname and not is_ip:
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])

        # Shortener check
        is_shortened = (hostname in cls._SHORTENER_DOMAINS) or (domain in cls._SHORTENER_DOMAINS)

        # Punycode check
        is_punycode = "xn--" in hostname

        # Lookalike pattern check (digits replacing letters: 0 for o, 1 for l/i)
        is_lookalike = False
        if not is_ip and hostname:
            if re.search(r"[a-z]+[0-9]+[a-z]+", hostname):
                is_lookalike = True

        # Suspicious keyword check
        reasons = []
        risk = 0

        if is_ip:
            risk += 45
            reasons.append("Direct IP address used as URL host (bypasses domain reputation)")

        if scheme == "http" and any(kw in (path + (query or "")).lower() for kw in ("login", "auth", "password", "bank")):
            risk += 35
            reasons.append("Insecure HTTP protocol used for authentication or credential target")

        if is_shortened:
            risk += 25
            reasons.append("URL shortener service hides final target destination")

        if is_punycode:
            risk += 40
            reasons.append("Internationalized domain name (IDN/Punycode) detected (potential homoglyph)")

        if is_lookalike:
            risk += 30
            reasons.append("Alphanumeric substitution pattern observed in hostname")

        # Keyword heuristics
        url_lower = original_url.lower()
        matched_kws = [kw for kw in cls._SUSPICIOUS_KEYWORDS if kw in url_lower]
        if matched_kws:
            risk += min(len(matched_kws) * 10, 30)
            reasons.append(f"Contains security-sensitive keywords: {', '.join(matched_kws[:3])}")

        # Final threat level classification
        risk = min(risk, 100)
        if risk >= 75:
            threat_level = "critical"
        elif risk >= 50:
            threat_level = "high"
        elif risk >= 25:
            threat_level = "suspicious"
        else:
            threat_level = "clean"

        return ExtractedUrlSchema(
            original_url=original_url,
            normalized_url=normalized,
            scheme=scheme,
            hostname=hostname or None,
            domain=domain or None,
            path=path,
            query=query,
            is_ip_based=is_ip,
            is_shortened=is_shortened,
            is_lookalike=is_lookalike,
            is_punycode=is_punycode,
            has_redirect=is_shortened,
            risk_score=risk,
            threat_level=threat_level,
            reason="; ".join(reasons) if reasons else "No anomalous characteristics detected",
            source_location="body",
        )

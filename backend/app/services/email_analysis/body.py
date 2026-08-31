import re
from typing import Dict, Any, List, Tuple, Optional
from bs4 import BeautifulSoup

class BodyAnalyzer:
    """Safe email body extraction and contextual linguistic intent threat signal scorer."""

    # Imperative / action credential harvesting phrases
    _CREDENTIAL_ACTION_PATTERNS = [
        re.compile(r"\b(verify|confirm|update|reset|validate|re-?authenticate|authenticate|enter)\s+(your\s+)?(password|passcode|credentials?|account|identity|mfa|login|profile)\b", re.IGNORECASE),
        re.compile(r"\b(click\s+here\s+to\s+(verify|log\s*in|sign\s*in|reset|update|access|view|sign|authenticate))\b", re.IGNORECASE),
        re.compile(r"\b(log\s*in|sign\s*in|authenticate)\s+to\s+(access|view|review|sign|verify|confirm|restore|retain|unlock|download|prevent)\b", re.IGNORECASE),
        re.compile(r"\b(account\s+requires\s+verification|confirm\s+your\s+login\s+credentials|authenticate\s+your\s+account)\b", re.IGNORECASE),
        re.compile(r"\b(unusual|suspicious)\s+activity\s+detected\b", re.IGNORECASE),
        re.compile(r"\b(mailbox\s+quota|storage\s+is\s+full|session\s+expired)\b", re.IGNORECASE),
        re.compile(r"\b(view\s+and\s+sign|access\s+document|electronic\s+signature)\b", re.IGNORECASE),
    ]

    # Coercive consequence & deadline urgency phrases
    _COERCIVE_URGENCY_PATTERNS = [
        re.compile(r"\b(account\s+(will\s+be\s+)?(suspended|terminated|locked|disabled|restricted|closed))\b", re.IGNORECASE),
        re.compile(r"\b(within\s+(24|48|2|1)\s+hours?|expires?\s+today|final\s+notice|immediate\s+compliance)\b", re.IGNORECASE),
        re.compile(r"\b(permanent\s+account\s+suspension|action\s+required\s+immediately|prevent\s+suspension)\b", re.IGNORECASE),
        re.compile(r"\b(immediate(ly)?|urgent(ly)?|prompt\s+attention|before\s+the\s+end\s+of\s+the\s+day)\b", re.IGNORECASE),
    ]

    # Monetary transfer / wire fraud patterns (BEC intent)
    _FINANCIAL_ACTION_PATTERNS = [
        re.compile(r"\b(wire\s+transfer|transfer\s+(the\s+)?funds|process\s+a\s+(confidential\s+)?wire|send\s+payment|arrange\s+(the\s+)?payment)\b", re.IGNORECASE),
        re.compile(r"\b(routing\s+number|swift\s+code|beneficiary\s+account|bank\s+account\s+details|updated\s+account)\b", re.IGNORECASE),
        re.compile(r"\b(direct\s+deposit\s+(update|change)|payroll\s+(direct\s+deposit|update))\b", re.IGNORECASE),
        re.compile(r"\b(overdue\s+invoice\s+payment|unpaid\s+balance\s+remittance|remit\s+payment|remit\s+funds|transfer\s+completed)\b", re.IGNORECASE),
        re.compile(r"\b(send\s+\$?\d+|following\s+account\s+today|account\s+today|send\s+the\s+funds)\b", re.IGNORECASE),
    ]

    # Executive impersonation & confidentiality mandates (BEC intent)
    _IMPERSONATION_PATTERNS = [
        re.compile(r"\b(i\s+am\s+(currently\s+)?in\s+a\s+meeting|in\s+a\s+conference|traveling)\b", re.IGNORECASE),
        re.compile(r"\b(strictly\s+confidential|do\s+not\s+discuss|keep\s+this\s+confidential|private\s+acquisition)\b", re.IGNORECASE),
        re.compile(r"\b(do\s+not\s+call|email\s+only|reach\s+me\s+via\s+email)\b", re.IGNORECASE),
        re.compile(r"\b(chief\s+executive\s+officer|\bceo\b|\bcfo\b|board\s+of\s+directors|executive\s+office)\b", re.IGNORECASE),
        re.compile(r"\b(microsoft\s+security\s+team|it\s+support\s+desk|security\s+team|bank\s+representative)\b", re.IGNORECASE),
    ]

    # Currency amount regex
    _CURRENCY_REGEX = re.compile(r"(\$|€|£|USD|EUR|GBP)\s*([0-9]{1,3}(,[0-9]{3})+(\.[0-9]{2})?|[0-9]+(\.[0-9]{2})?)", re.IGNORECASE)

    @classmethod
    def extract_safe_text(cls, body_plain: str, body_html: str) -> Tuple[str, str]:
        """Strip active HTML elements and return safe text."""
        clean_html_text = ""
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for tag in soup(["script", "style", "iframe", "object", "embed", "applet", "svg"]):
                    tag.decompose()
                clean_html_text = soup.get_text(separator=" ", strip=True)
            except Exception:
                clean_html_text = re.sub(r"<[^>]+>", " ", body_html)

        full_combined_text = f"{body_plain or ''} {clean_html_text}".strip()
        preview = full_combined_text[:500] if full_combined_text else "No textual content in message."
        return full_combined_text, preview

    @classmethod
    def analyze_linguistics(cls, text: str, subject: Optional[str] = None) -> Dict[str, Any]:
        """
        Contextual linguistic intent analyzer.
        Differentiates topic discussion from coercive calls-to-action.
        """
        combined = f"{subject or ''} {text}"
        combined_lower = combined.lower()

        # 1. Credential Intent (Action + Target)
        cred_matches = []
        for pat in cls._CREDENTIAL_ACTION_PATTERNS:
            found = pat.findall(combined)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    cred_matches.append(val.strip())

        # If subject/body is purely conversational discussion (e.g. "discuss password security", "password policy")
        is_topic_only = bool(re.search(r"\b(discuss|review|meeting\s+about|policy\s+on|training\s+on)\s+(password|security|invoices?)\b", combined_lower))
        if is_topic_only and not re.search(r"\b(verify|log\s*in|click\s+here|reset|suspended)\b", combined_lower):
            credential_score = 0.0
            cred_matches = []
        else:
            credential_score = min(len(cred_matches) * 0.40, 1.0)

        # 2. Financial / Wire Intent
        fin_matches = []
        for pat in cls._FINANCIAL_ACTION_PATTERNS:
            found = pat.findall(combined)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    fin_matches.append(val.strip())

        currency_matches = cls._CURRENCY_REGEX.findall(combined)
        if currency_matches:
            for curr in currency_matches:
                fin_matches.append(f"Currency Amount ({curr[0]}{curr[1]})")

        # Plain mentions of "invoice" without remittance/wire context
        has_wire_or_amount = bool(currency_matches or any("wire" in m.lower() or "transfer" in m.lower() or "deposit" in m.lower() or "payment" in m.lower() for m in fin_matches))
        if not has_wire_or_amount:
            financial_score = 0.0
            fin_matches = []
        else:
            financial_score = min(len(fin_matches) * 0.35, 1.0)

        # 3. Urgency & Coercion Intent
        urgency_matches = []
        for pat in cls._COERCIVE_URGENCY_PATTERNS:
            found = pat.findall(combined)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    urgency_matches.append(val.strip())

        # If it's a routine meeting notification with "urgent" (e.g., "Urgent meeting at 3 PM")
        is_routine_urgent_meeting = bool(re.search(r"\b(urgent\s+(project\s+)?meeting|meeting\s+at\s+\d+)\b", combined_lower))
        has_consequence_threat = bool(re.search(r"\b(suspend|terminat|lock|penalt|disabl|within\s+\d+\s+hours?|final\s+notice)\b", combined_lower))
        
        if is_routine_urgent_meeting and not has_consequence_threat:
            urgency_score = 0.15
        else:
            urgency_score = min(len(urgency_matches) * 0.35, 1.0)

        # 4. Impersonation & Authority Intent
        imp_matches = []
        for pat in cls._IMPERSONATION_PATTERNS:
            found = pat.findall(combined)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    imp_matches.append(val.strip())

        impersonation_score = min(len(imp_matches) * 0.35, 1.0)

        return {
            "urgency_score": round(float(urgency_score), 2),
            "credential_request_score": round(float(credential_score), 2),
            "financial_request_score": round(float(financial_score), 2),
            "impersonation_score": round(float(impersonation_score), 2),
            "matches": {
                "urgency": urgency_matches,
                "credential": cred_matches,
                "financial": fin_matches,
                "impersonation": imp_matches,
            }
        }

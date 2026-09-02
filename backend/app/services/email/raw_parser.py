"""
Raw Email Sanitization and Parsing Utilities.
Safely converts raw email text strings into bytes without choking on UTF-16 surrogates or malformed pastes.
Provides plaintext regex heuristic fallback for attachment detection in unstructured raw email bodies.
"""
import email
from email import policy
import re
from typing import Optional, List, Dict, Any


def sanitize_surrogates(text: str) -> str:
    """Strip unencodable UTF-16 surrogate pairs and malformed codepoints."""
    if not isinstance(text, str):
        return ""
    return re.sub(r"[\ud800-\udfff]", "", text)


def clean_surrogates(text: str) -> str:
    """Eliminate UTF-16 surrogates and unpaired codes before JSON serialization or decoding."""
    if not isinstance(text, str):
        return text if text is not None else ""
    cleaned = sanitize_surrogates(text)
    try:
        return cleaned.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
    except Exception:
        return cleaned


def safe_str_to_bytes(text: str) -> bytes:
    """Convert cleaned text to bytes, guaranteeing no codec crashes."""
    clean_text = sanitize_surrogates(text)
    try:
        return clean_text.encode("utf-8", errors="ignore")
    except Exception:
        return clean_text.encode("latin-1", errors="replace")


def safe_to_bytes(text: str) -> bytes:
    """Safely convert sanitized text to bytes without crashing on codecs."""
    return safe_str_to_bytes(text)


def sanitize_raw_email_text(raw_text: str) -> bytes:
    """Safely convert raw email string into bytes without choking on UTF-16 surrogates."""
    return safe_str_to_bytes(raw_text)


def parse_raw_message_safe(raw_text_or_bytes):
    """Parse raw email into an EmailMessage using surrogate-safe byte handling."""
    if isinstance(raw_text_or_bytes, str):
        safe_bytes = safe_str_to_bytes(raw_text_or_bytes)
    else:
        safe_bytes = raw_text_or_bytes
    return email.message_from_bytes(safe_bytes, policy=policy.default)


ATTACHMENT_REGEX = re.compile(
    r'(?:Attachment|Attached|File):\s*([\w\.-]+\.(?:exe|vbs|bat|cmd|scr|pdf\.exe|pdf\.vbs|docm|xlsm|iso|js))',
    re.IGNORECASE
)


def extract_plaintext_attachments(text: str) -> List[Dict[str, Any]]:
    """
    Plaintext heuristic fallback for plain text inputs lacking multipart MIME boundaries.
    Extracts dangerous payload filenames from 'Attachment: ...', 'File: ...', etc.
    """
    if not text:
        return []
    matches = ATTACHMENT_REGEX.findall(text)
    attachments: List[Dict[str, Any]] = []
    for matched_filename in matches:
        matched_filename = matched_filename.strip()
        is_double = any(x in matched_filename.lower() for x in [".pdf.exe", ".pdf.vbs", ".doc.exe"])
        threat_flag = "SUSPICIOUS_DOUBLE_EXTENSION" if is_double else "EXECUTABLE_PAYLOAD"
        attachments.append({
            "filename": matched_filename,
            "is_malicious": True,
            "threat_flag": threat_flag,
            "file_size": 0,
            "risk_score": 95,
            "content_type": "application/octet-stream",
            "content_disposition": "attachment",
            "payload_bytes": b"",
        })
    return attachments


__all__ = [
    "sanitize_surrogates",
    "clean_surrogates",
    "safe_str_to_bytes",
    "safe_to_bytes",
    "sanitize_raw_email_text",
    "parse_raw_message_safe",
    "ATTACHMENT_REGEX",
    "extract_plaintext_attachments",
]

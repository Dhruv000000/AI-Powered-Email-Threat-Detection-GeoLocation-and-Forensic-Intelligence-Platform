import email
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import Dict, Any, List, Optional, Tuple
from app.core.logging import logger

class ParsedEmailData:
    def __init__(self):
        self.headers: List[Tuple[str, str]] = []
        self.metadata: Dict[str, Any] = {
            "from": None,
            "from_display_name": None,
            "from_email": None,
            "from_domain": None,
            "to": [],
            "cc": [],
            "bcc": [],
            "reply_to": None,
            "return_path": None,
            "subject": None,
            "date": None,
            "message_id": None,
        }
        self.body_plain: str = ""
        self.body_html: str = ""
        self.attachments_raw: List[Dict[str, Any]] = []


class EmailParser:
    """RFC 822 / MIME Email Parser using standard Python email package with policy.default."""

    @staticmethod
    def parse_bytes(raw_bytes: bytes) -> ParsedEmailData:
        try:
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception as e:
            logger.error(f"BytesParser failed on payload: {e}")
            raise ValueError(f"Failed to parse email payload: {e}")

        data = ParsedEmailData()

        # 1. Preserve all headers in original order
        for name, value in msg.items():
            data.headers.append((str(name), str(value)))

        # 2. Extract Primary Envelope Metadata
        from_hdr = msg.get("from", "")
        data.metadata["from"] = str(from_hdr) if from_hdr else None
        
        # Parse display name and email address safely
        from_addrs = msg.get("from")
        if from_addrs and hasattr(from_addrs, "addresses") and from_addrs.addresses:
            addr = from_addrs.addresses[0]
            data.metadata["from_display_name"] = addr.display_name or None
            data.metadata["from_email"] = addr.addr_spec or None
            data.metadata["from_domain"] = addr.domain.lower() if addr.domain else None
        elif from_hdr:
            # Fallback simple string extraction
            raw_str = str(from_hdr)
            if "<" in raw_str and ">" in raw_str:
                em = raw_str.split("<")[1].split(">")[0].strip()
                data.metadata["from_email"] = em
                data.metadata["from_domain"] = em.split("@")[-1].lower() if "@" in em else None
                data.metadata["from_display_name"] = raw_str.split("<")[0].replace('"', '').strip() or None
            else:
                data.metadata["from_email"] = raw_str.strip()
                data.metadata["from_domain"] = raw_str.split("@")[-1].lower() if "@" in raw_str else None

        # To / CC / BCC
        for field in ("to", "cc", "bcc"):
            val = msg.get(field)
            if val and hasattr(val, "addresses"):
                data.metadata[field] = [a.addr_spec for a in val.addresses if a.addr_spec]
            elif val:
                data.metadata[field] = [str(val).strip()]

        # Reply-To
        reply_to_hdr = msg.get("reply-to")
        if reply_to_hdr and hasattr(reply_to_hdr, "addresses") and reply_to_hdr.addresses:
            data.metadata["reply_to"] = reply_to_hdr.addresses[0].addr_spec
        elif reply_to_hdr:
            raw_str = str(reply_to_hdr)
            if "<" in raw_str and ">" in raw_str:
                data.metadata["reply_to"] = raw_str.split("<")[1].split(">")[0].strip()
            else:
                data.metadata["reply_to"] = raw_str.strip()

        # Return-Path
        ret_path = msg.get("return-path")
        if ret_path:
            raw_ret = str(ret_path).strip().replace("<", "").replace(">", "")
            data.metadata["return_path"] = raw_ret

        # Subject, Date, Message-ID
        data.metadata["subject"] = str(msg.get("subject", "")) or None
        data.metadata["date"] = str(msg.get("date", "")) or None
        data.metadata["message_id"] = str(msg.get("message-id", "")).strip() or None

        # 3. Extract Plain Text & HTML Body and Attachments
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("content-disposition", ""))
                
                # Check for attachment
                if "attachment" in content_disposition or part.get_filename():
                    raw_payload = part.get_payload(decode=True) or b""
                    data.attachments_raw.append({
                        "filename": part.get_filename() or "unnamed_attachment",
                        "content_type": content_type,
                        "content_disposition": content_disposition,
                        "payload_bytes": raw_payload,
                    })
                elif content_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            data.body_plain += content + "\n"
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            data.body_plain += payload.decode("utf-8", errors="replace") + "\n"
                elif content_type == "text/html":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            data.body_html += content + "\n"
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            data.body_html += payload.decode("utf-8", errors="replace") + "\n"
        else:
            # Single-part email
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if content_type == "text/html":
                        data.body_html = content
                    else:
                        data.body_plain = content
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded = payload.decode("utf-8", errors="replace")
                    if content_type == "text/html":
                        data.body_html = decoded
                    else:
                        data.body_plain = decoded

        return data

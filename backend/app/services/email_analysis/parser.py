import io
import re
import email
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import Dict, Any, List, Optional, Tuple
from app.core.logging import logger

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    import pdfplumber
    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False


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
    """RFC 822 / MIME and PDF Email Parser supporting .eml, .msg, .txt, and .pdf forensic ingestion."""

    @staticmethod
    def parse_bytes(raw_bytes: bytes, filename: Optional[str] = None) -> ParsedEmailData:
        # Check if file is a PDF (Magic bytes %PDF or filename ends with .pdf)
        is_pdf = raw_bytes.startswith(b"%PDF-") or (filename and filename.lower().endswith(".pdf"))
        if is_pdf:
            return EmailParser._parse_pdf(raw_bytes, filename or "exported_email.pdf")

        return EmailParser._parse_rfc822(raw_bytes)

    @staticmethod
    def _parse_rfc822(raw_bytes: bytes) -> ParsedEmailData:
        try:
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception:
            try:
                msg = email.message_from_bytes(raw_bytes, policy=policy.default)
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

        # Plaintext Heuristic Fallback: parse raw body for attachment declarations if no MIME attachments were extracted
        if len(data.attachments_raw) == 0:
            text_to_search = data.body_plain or ""
            if not text_to_search:
                try:
                    text_to_search = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    text_to_search = ""
            if text_to_search:
                from app.services.email.raw_parser import extract_plaintext_attachments
                detected_atts = extract_plaintext_attachments(text_to_search)
                if detected_atts:
                    data.attachments_raw.extend(detected_atts)

        return data

    @staticmethod
    def _parse_pdf(raw_bytes: bytes, filename: str) -> ParsedEmailData:
        """Parses exported email PDF artifacts, extracting text, embedded URIs, and RFC headers."""
        data = ParsedEmailData()
        extracted_text = ""
        extracted_uris: List[str] = []

        if PDFPLUMBER_AVAILABLE:
            try:
                with pdfplumber.open(io.BytesIO(raw_bytes)) as pdf:
                    plumber_text = ""
                    for page in pdf.pages:
                        page_txt = page.extract_text() or ""
                        plumber_text += page_txt + "\n"
                        if hasattr(page, "hyperlinks") and page.hyperlinks:
                            for link in page.hyperlinks:
                                if isinstance(link, dict) and "uri" in link and link["uri"]:
                                    extracted_uris.append(str(link["uri"]))
                    if plumber_text.strip():
                        extracted_text = plumber_text
            except Exception as e:
                logger.debug(f"pdfplumber extraction fallback: {e}")

        if not extracted_text and PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
                for page in reader.pages:
                    page_text = page.extract_text() or ""
                    extracted_text += page_text + "\n"

                    # Extract PDF annotations (links, buttons)
                    if "/Annots" in page:
                        annots = page["/Annots"]
                        if isinstance(annots, list):
                            for annot in annots:
                                annot_obj = annot.get_object() if hasattr(annot, "get_object") else annot
                                if annot_obj and "/A" in annot_obj:
                                    action = annot_obj["/A"]
                                    if "/URI" in action:
                                        uri_val = str(action["/URI"])
                                        extracted_uris.append(uri_val)

                # Extract embedded file attachments if present
                if hasattr(reader, "attachments") and reader.attachments:
                    for att_name, att_bytes_list in reader.attachments.items():
                        for b in att_bytes_list:
                            data.attachments_raw.append({
                                "filename": att_name,
                                "content_type": "application/octet-stream",
                                "content_disposition": f'attachment; filename="{att_name}"',
                                "payload_bytes": b,
                            })
            except Exception as e:
                logger.warning(f"pypdf extraction error, falling back to raw stream decoding: {e}")
                extracted_text = raw_bytes.decode("latin-1", errors="replace")
        elif not extracted_text:
            extracted_text = raw_bytes.decode("latin-1", errors="replace")

        # Fallback URI regex extraction from raw bytes
        if not extracted_uris:
            uri_matches = re.findall(r"https?://[^\s<>\"\'\)]+", extracted_text)
            extracted_uris.extend(uri_matches)

        # Append extracted URIs into text stream if not already present
        if extracted_uris:
            extracted_text += "\n\n[Extracted PDF Links]\n" + "\n".join(set(extracted_uris))

        data.body_plain = extracted_text.strip()
        data.body_html = f"<pre>{extracted_text.strip()}</pre>"

        # Parse printed RFC email headers from text stream
        lines = extracted_text.splitlines()
        header_map = {}
        for line in lines:
            line_str = line.strip()
            # Match From: ...
            if re.match(r"^From:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^From:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["From"] = val
            elif re.match(r"^To:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^To:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["To"] = val
            elif re.match(r"^Subject:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^Subject:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["Subject"] = val
            elif re.match(r"^Date:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^Date:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["Date"] = val
            elif re.match(r"^Reply-To:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^Reply-To:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["Reply-To"] = val
            elif re.match(r"^Message-ID:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^Message-ID:\s*", "", line_str, flags=re.IGNORECASE).strip()
                header_map["Message-ID"] = val
            elif re.match(r"^Received:\s*", line_str, re.IGNORECASE):
                val = re.sub(r"^Received:\s*", "", line_str, flags=re.IGNORECASE).strip()
                data.headers.append(("Received", val))

        # Populate ParsedEmailData metadata
        from_hdr = header_map.get("From")
        if from_hdr:
            data.metadata["from"] = from_hdr
            if "<" in from_hdr and ">" in from_hdr:
                em = from_hdr.split("<")[1].split(">")[0].strip()
                data.metadata["from_email"] = em
                data.metadata["from_domain"] = em.split("@")[-1].lower() if "@" in em else None
                data.metadata["from_display_name"] = from_hdr.split("<")[0].replace('"', '').strip() or None
            else:
                data.metadata["from_email"] = from_hdr.strip()
                data.metadata["from_domain"] = from_hdr.split("@")[-1].lower() if "@" in from_hdr else None
        else:
            clean_fn = filename.replace(".pdf", "").replace("_", " ")
            data.metadata["from_email"] = "pdf-ingestion@forensic-origin.local"
            data.metadata["from_domain"] = "forensic-origin.local"
            data.metadata["from_display_name"] = f"PDF Artifact ({clean_fn})"

        to_hdr = header_map.get("To")
        if to_hdr:
            data.metadata["to"] = [t.strip() for t in to_hdr.split(",") if t.strip()]

        data.metadata["subject"] = header_map.get("Subject") or f"Forensic PDF Analysis: {filename}"
        data.metadata["date"] = header_map.get("Date") or None
        data.metadata["reply_to"] = header_map.get("Reply-To") or None
        data.metadata["message_id"] = header_map.get("Message-ID") or f"<pdf-{hash(filename)}@aegis-dfir.local>"

        # Push mapped headers
        for k, v in header_map.items():
            if k != "Received":
                data.headers.append((k, v))
        data.headers.append(("X-Ingestion-Source", f"AEGIS PDF Ingestion ({filename})"))

        return data

import hashlib
from typing import List, Dict, Any, Tuple
from app.schemas.email_analysis import AttachmentMetadataSchema

class AttachmentAnalyzer:
    """Forensic attachment metadata extraction and static threat signal analyzer (Non-Executing)."""

    _DANGEROUS_EXTENSIONS = {
        "exe", "scr", "bat", "vbs", "js", "jse", "ps1", "iso", "img", "hta", "cpl",
        "wsf", "wsh", "pif", "cmd", "com", "gadget", "jar", "app", "dmg"
    }

    _MACRO_EXTENSIONS = {
        "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "ppsm"
    }

    _DOCUMENT_EXTENSIONS = {
        "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "rtf", "csv"
    }

    @classmethod
    def analyze_attachments(cls, raw_attachments: List[Dict[str, Any]]) -> Tuple[List[AttachmentMetadataSchema], str]:
        results: List[AttachmentMetadataSchema] = []
        overall_assessment = "clean"

        for att in raw_attachments:
            filename = att.get("filename", "unnamed_attachment")
            content_type = att.get("content_type", "application/octet-stream")
            content_disp = att.get("content_disposition")
            payload = att.get("payload_bytes", b"")
            size_bytes = len(payload)

            # Compute SHA-256 hash of payload
            sha256 = hashlib.sha256(payload).hexdigest()

            # Analyze filename extensions
            parts = filename.lower().split(".")
            is_double_ext = False
            is_executable = False
            is_suspicious = False
            detected_signals: List[str] = []

            if len(parts) >= 3:
                # e.g. invoice.pdf.exe
                primary_ext = parts[-2]
                final_ext = parts[-1]
                if primary_ext in cls._DOCUMENT_EXTENSIONS and final_ext in (cls._DANGEROUS_EXTENSIONS | cls._MACRO_EXTENSIONS):
                    is_double_ext = True
                    is_suspicious = True
                    detected_signals.append(f"Deceptive double-extension detected: '{primary_ext}.{final_ext}' masquerading as a document")

            final_ext = parts[-1] if len(parts) >= 2 else ""

            if final_ext in cls._DANGEROUS_EXTENSIONS:
                is_executable = True
                is_suspicious = True
                detected_signals.append(f"High-risk executable/script extension: '.{final_ext}'")

            if final_ext in cls._MACRO_EXTENSIONS:
                is_suspicious = True
                detected_signals.append(f"VBA/Office macro-enabled file format: '.{final_ext}'")

            if content_type in ("application/x-msdownload", "application/x-executable", "application/x-sh", "application/x-bat"):
                is_executable = True
                is_suspicious = True
                detected_signals.append(f"Executable MIME content type: '{content_type}'")

            if is_suspicious:
                if is_executable or is_double_ext:
                    overall_assessment = "suspicious"
                elif overall_assessment != "suspicious":
                    overall_assessment = "warning"

            results.append(
                AttachmentMetadataSchema(
                    filename=filename,
                    content_type=content_type,
                    content_disposition=content_disp,
                    size_bytes=size_bytes,
                    sha256=sha256,
                    is_double_extension=is_double_ext,
                    is_executable=is_executable,
                    is_suspicious=is_suspicious,
                    detected_signals=detected_signals,
                )
            )

        return results, overall_assessment

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
import email
from email.message import Message
from email.policy import default as default_policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from app.core.config import settings
from app.core.errors import EmailIngestionError
from app.schemas.email import (
    AttachmentMetadata,
    EmailAddress,
    EmailNormalized,
    ReceivedHop,
    URLEntry,
)

# Known URL shorteners set for passive URL classification
KNOWN_SHORTENERS: Set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly", "cutt.ly"
}

# High-risk/suspicious TLDs set for passive URL classification
SUSPICIOUS_TLDS: Set[str] = {
    "zip", "mov", "top", "xyz", "work", "click", "loan", "gq", "cf", "tk", "ml", "ga"
}

# File extensions for attachment classification
EXECUTABLE_EXTENSIONS: Set[str] = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".jar", ".scr", ".com", ".hta"}
MACRO_EXTENSIONS: Set[str] = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}
ARCHIVE_EXTENSIONS: Set[str] = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".iso", ".tgz"}


class EmailIngestionService:
    """Service for safely parsing, normalizing, and extracting metadata from raw emails."""

    def parse_raw_email(
        self,
        raw_content: Union[bytes, str],
        message_id_override: Optional[str] = None
    ) -> EmailNormalized:
        """Parses a raw RFC 5322 MIME email payload into a canonical EmailNormalized model."""
        if raw_content is None:
            raise EmailIngestionError("Email payload cannot be None")

        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        else:
            raw_bytes = raw_content

        if len(raw_bytes) > settings.MAX_RAW_EMAIL_BYTES:
            raise EmailIngestionError(
                f"Email payload size ({len(raw_bytes)} bytes) exceeds maximum limit of {settings.MAX_RAW_EMAIL_BYTES} bytes"
            )

        try:
            msg = email.message_from_bytes(raw_bytes, policy=default_policy)
        except Exception as exc:
            raise EmailIngestionError(f"Failed to parse raw MIME email: {str(exc)}") from exc

        return self._normalize_message(msg, raw_bytes, message_id_override)

    def parse_dict(self, data: Dict[str, Any]) -> EmailNormalized:
        """Parses a structured dictionary payload into a canonical EmailNormalized model."""
        if not isinstance(data, dict):
            raise EmailIngestionError("Input data must be a dictionary")

        try:
            # Normalize sender
            raw_sender = data.get("sender") or data.get("from") or ""
            sender = self._normalize_address_item(raw_sender)

            # Normalize recipients
            raw_recipients = data.get("recipients") or data.get("to") or []
            if isinstance(raw_recipients, (str, dict)):
                raw_recipients = [raw_recipients]
            recipients = [self._normalize_address_item(r) for r in raw_recipients]

            # Normalize reply_to
            raw_reply_to = data.get("reply_to")
            reply_to = None
            if raw_reply_to:
                if isinstance(raw_reply_to, (str, dict)):
                    raw_reply_to = [raw_reply_to]
                reply_to = [self._normalize_address_item(r) for r in raw_reply_to]

            message_id = str(data.get("message_id") or data.get("id") or self._generate_fallback_msg_id(data))
            subject = str(data.get("subject") or "")
            headers = {str(k): str(v) for k, v in (data.get("headers") or {}).items()}

            body = str(data.get("body") or data.get("body_text_preview") or "")
            body_preview = body[:1000] if body else None

            # Attachment metadata
            attachments = []
            for att in (data.get("attachments") or [])[:settings.MAX_ATTACHMENTS]:
                if isinstance(att, dict):
                    filename = str(att.get("filename") or "unnamed")
                    content_type = str(att.get("content_type") or "application/octet-stream")
                    size = int(att.get("size_bytes") or att.get("size") or 0)
                    ext = self._get_extension(filename)
                    attachments.append(
                        AttachmentMetadata(
                            filename=filename,
                            content_type=content_type,
                            size_bytes=max(0, size),
                            md5_hash=att.get("md5_hash"),
                            sha256_hash=att.get("sha256_hash"),
                            mime_type_detected=att.get("mime_type_detected") or content_type,
                            is_executable=ext in EXECUTABLE_EXTENSIONS or bool(att.get("is_executable")),
                            has_macro=ext in MACRO_EXTENSIONS or bool(att.get("has_macro")),
                            is_archive=ext in ARCHIVE_EXTENSIONS or bool(att.get("is_archive")),
                        )
                    )

            # Extract URLs
            extracted_urls = self._extract_urls(body, data.get("urls"))

            # Parse Received Hops
            received_hops = []
            for hop in data.get("received_hops") or []:
                if isinstance(hop, dict):
                    received_hops.append(
                        ReceivedHop(
                            by_host=hop.get("by_host"),
                            from_host=hop.get("from_host"),
                            ip_address=hop.get("ip_address"),
                            timestamp=self._parse_timestamp(hop.get("timestamp")),
                            delay_seconds=hop.get("delay_seconds"),
                        )
                    )

            timestamp = self._parse_timestamp(data.get("timestamp")) or datetime.now(timezone.utc)

            return EmailNormalized(
                message_id=message_id,
                sender=sender,
                recipients=recipients,
                reply_to=reply_to,
                subject=subject,
                headers=headers,
                body_text_preview=body_preview,
                attachments=attachments,
                urls=extracted_urls,
                received_hops=received_hops,
                timestamp=timestamp,
                mailbox_id=data.get("mailbox_id"),
                user_id=data.get("user_id"),
            )
        except EmailIngestionError:
            raise
        except Exception as exc:
            raise EmailIngestionError(f"Failed to normalize dictionary payload: {str(exc)}") from exc

    def _normalize_message(
        self,
        msg: Message,
        raw_bytes: bytes,
        message_id_override: Optional[str]
    ) -> EmailNormalized:
        """Helper to extract normalized structure from parsed email.message.Message."""
        headers: Dict[str, str] = {}
        for k, v in msg.items():
            val_str = str(v)
            if len(val_str) > 10000:
                val_str = val_str[:10000]
            headers[str(k)] = val_str

        message_id = message_id_override or msg.get("Message-ID") or self._generate_fallback_msg_id_from_bytes(raw_bytes)
        subject = msg.get("Subject") or ""

        # Senders & Recipients
        from_hdr = msg.get("From", "")
        sender = self._normalize_address_item(from_hdr)

        to_hdr = msg.get("To", "")
        cc_hdr = msg.get("Cc", "")
        recipients_list = getaddresses([to_hdr, cc_hdr])
        recipients = [
            EmailAddress(address=addr.lower(), name=name if name else None)
            for name, addr in recipients_list if addr
        ]
        if not recipients and sender.address:
            # Fallback if To/Cc headers missing
            recipients = [EmailAddress(address="unknown@target.local")]

        reply_to_hdr = msg.get("Reply-To", "")
        reply_to_list = getaddresses([reply_to_hdr])
        reply_to = [
            EmailAddress(address=addr.lower(), name=name if name else None)
            for name, addr in reply_to_list if addr
        ] if reply_to_list else None

        # Parts extraction
        plain_text_parts: List[str] = []
        html_parts: List[str] = []
        attachments: List[AttachmentMetadata] = []
        part_count = 0

        for part in msg.walk():
            part_count += 1
            if part_count > settings.MAX_MIME_PARTS:
                break

            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            is_attachment = "attachment" in content_disposition.lower() or bool(filename)

            if is_attachment and len(attachments) < settings.MAX_ATTACHMENTS:
                att_filename = filename or "unnamed_attachment"
                payload_bytes = part.get_payload(decode=True) or b""
                ext = self._get_extension(att_filename)
                md5_h = hashlib.md5(payload_bytes).hexdigest() if payload_bytes else None
                sha256_h = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else None
                c_type = part.get_content_type()

                attachments.append(
                    AttachmentMetadata(
                        filename=att_filename,
                        content_type=c_type,
                        size_bytes=len(payload_bytes),
                        md5_hash=md5_h,
                        sha256_hash=sha256_h,
                        mime_type_detected=c_type,
                        is_executable=ext in EXECUTABLE_EXTENSIONS,
                        has_macro=ext in MACRO_EXTENSIONS,
                        is_archive=ext in ARCHIVE_EXTENSIONS,
                    )
                )
            else:
                c_type = part.get_content_type()
                if c_type == "text/plain":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            plain_text_parts.append(content)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_text_parts.append(payload.decode("utf-8", errors="replace"))
                elif c_type == "text/html":
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            html_parts.append(content)
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_parts.append(payload.decode("utf-8", errors="replace"))

        # Body preview safely (unrendered)
        combined_text = "\n".join(plain_text_parts) if plain_text_parts else "\n".join(html_parts)
        body_text_preview = combined_text[:1000].strip() if combined_text else None

        # Passive URL Extraction
        urls = self._extract_urls(combined_text)

        # Received Hops
        received_headers = msg.get_all("Received", [])
        received_hops = self._parse_received_headers(received_headers)

        # Date header timestamp
        date_hdr = msg.get("Date")
        timestamp = None
        if date_hdr:
            try:
                timestamp = parsedate_to_datetime(date_hdr)
                if timestamp and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
            except Exception:
                timestamp = None
        if not timestamp:
            timestamp = datetime.now(timezone.utc)

        return EmailNormalized(
            message_id=str(message_id),
            sender=sender,
            recipients=recipients,
            reply_to=reply_to,
            subject=str(subject),
            headers=headers,
            body_text_preview=body_text_preview,
            attachments=attachments,
            urls=urls,
            received_hops=received_hops,
            timestamp=timestamp,
        )

    def _normalize_address_item(self, item: Any) -> EmailAddress:
        """Helper to parse a single address input into EmailAddress model."""
        if isinstance(item, dict):
            return EmailAddress(
                address=str(item.get("address") or "").lower(),
                name=item.get("name")
            )
        if isinstance(item, EmailAddress):
            return item

        raw_str = str(item or "")
        name, addr = parseaddr(raw_str)
        if not addr and "@" in raw_str:
            addr = raw_str.strip()
            name = ""

        return EmailAddress(
            address=addr.lower() if addr else "unknown@domain.local",
            name=name if name else None
        )

    def _extract_urls(
        self,
        body_text: str,
        provided_urls: Optional[List[Any]] = None
    ) -> List[URLEntry]:
        """Passively extracts URL entries without network lookups or request execution."""
        extracted: Dict[str, URLEntry] = {}

        # If explicit provided URLs exist
        if provided_urls:
            for item in provided_urls:
                if len(extracted) >= settings.MAX_EXTRACTED_URLS:
                    break
                if isinstance(item, dict):
                    url_val = item.get("url", "")
                    if url_val and url_val not in extracted:
                        extracted[url_val] = self._create_url_entry(url_val)
                elif isinstance(item, str) and item not in extracted:
                    extracted[item] = self._create_url_entry(item)

        # Passive Regex extraction from body text
        if body_text and len(extracted) < settings.MAX_EXTRACTED_URLS:
            url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
            matches = url_pattern.findall(body_text)
            for url in matches:
                if len(extracted) >= settings.MAX_EXTRACTED_URLS:
                    break
                # Clean trailing punctuation
                clean_url = url.rstrip(".,);]")
                if clean_url not in extracted:
                    extracted[clean_url] = self._create_url_entry(clean_url)

        return list(extracted.values())

    def _create_url_entry(self, url: str) -> URLEntry:
        """Constructs URLEntry passively using urllib.parse."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(":")[0].lower() if parsed.netloc else None
            is_ip = False
            if domain:
                try:
                    ipaddress.ip_address(domain)
                    is_ip = True
                except ValueError:
                    is_ip = False

            is_shortened = domain in KNOWN_SHORTENERS if domain else False
            ext = self._get_extension(domain) if domain else ""
            tld = ext.lstrip(".") if ext else (domain.split(".")[-1] if domain and "." in domain else "")
            suspicious_tld = tld in SUSPICIOUS_TLDS

            return URLEntry(
                url=url,
                domain=domain,
                is_ip=is_ip,
                is_shortened=is_shortened,
                suspicious_tld=suspicious_tld,
            )
        except Exception:
            return URLEntry(url=url)

    def _parse_received_headers(self, received_list: List[str]) -> List[ReceivedHop]:
        """Passively parses Received header entries."""
        hops: List[ReceivedHop] = []
        ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

        for rec in received_list:
            rec_str = str(rec)
            from_match = re.search(r'from\s+([^\s;]+)', rec_str, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s;]+)', rec_str, re.IGNORECASE)
            ip_match = ip_regex.search(rec_str)

            from_host = from_match.group(1) if from_match else None
            by_host = by_match.group(1) if by_match else None
            ip_addr = ip_match.group(0) if ip_match else None

            # Date section is usually after semicolon ';'
            timestamp = None
            if ";" in rec_str:
                date_part = rec_str.split(";")[-1].strip()
                try:
                    timestamp = parsedate_to_datetime(date_part)
                    if timestamp and timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                except Exception:
                    timestamp = None

            hops.append(
                ReceivedHop(
                    by_host=by_host,
                    from_host=from_host,
                    ip_address=ip_addr,
                    timestamp=timestamp,
                )
            )
        return hops

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Safely parses timestamp inputs into timezone-aware datetime."""
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                return None
        return None

    def _get_extension(self, filename: str) -> str:
        if not filename or "." not in filename:
            return ""
        return "." + filename.rsplit(".", 1)[-1].lower()

    def _generate_fallback_msg_id(self, data: Dict[str, Any]) -> str:
        raw_str = f"{data.get('sender')}-{data.get('subject')}-{data.get('timestamp')}"
        h = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]
        return f"<generated-{h}@mailtrace.local>"

    def _generate_fallback_msg_id_from_bytes(self, raw_bytes: bytes) -> str:
        h = hashlib.sha256(raw_bytes).hexdigest()[:16]
        return f"<generated-{h}@mailtrace.local>"
